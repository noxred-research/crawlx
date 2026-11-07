use super::{Dictionary, Object, ObjectId, Reader, Stream, StringFormat};
use crate::Error;
use crate::content::*;
use crate::error;
use crate::xref::*;
use std::collections::HashSet;
use std::str::{self, FromStr};

use nom::branch::alt;
use nom::bytes::complete::{tag, take, take_while, take_while_m_n, take_while1};
use nom::character::complete::multispace1;
use nom::character::complete::{digit0, digit1, one_of};
use nom::character::complete::{space0, space1};
use nom::combinator::cut;
use nom::combinator::{map, map_opt, map_res, opt, verify};
use nom::error::{ErrorKind, ParseError};
use nom::multi::{fold_many0, many0, many0_count};
use nom::sequence::{delimited, pair, preceded, separated_pair, terminated};
use nom::{AsChar, IResult, Input, Parser};

pub(crate) mod cmap_parser;

pub(crate) type ParserInput<'a> = &'a [u8];
// Change this to something else that implements ParseError to get a
// different error type out of nom.
pub(crate) type NomError<'a> = nom::error::Error<ParserInput<'a>>;

pub(crate) type NomResult<'a, O, E = NomError<'a>> = IResult<ParserInput<'a>, O, E>;

#[inline]
fn strip_nom<O>(r: NomResult<O>) -> Option<O> {
    r.ok().map(|(_, o)| o)
}

#[inline]
fn convert_result<O, E>(result: Result<O, E>, input: ParserInput, error_kind: ErrorKind) -> NomResult<O> {
    result.map(|o| (input, o)).map_err(|_| {
        // this is a unit bind if NomError = ()
        let err: NomError = nom::error::Error::from_error_kind(input, error_kind);
        nom::Err::Error(err)
    })
}

#[inline]
fn offset_stream(object: &mut Object, offset: usize) {
    if let Object::Stream(stream) = object {
        stream.start_position = stream.start_position.and_then(|sp| sp.checked_add(offset));
    }
}

pub(crate) fn eol(input: ParserInput) -> NomResult<ParserInput> {
    alt((tag(&b"\r\n"[..]), tag(&b"\n"[..]), tag(&b"\r"[..]))).parse(input)
}

pub(crate) fn comment(input: ParserInput) -> NomResult<()> {
    map((tag(&b"%"[..]), take_while(|c: u8| !b"\r\n".contains(&c)), eol), |_| ()).parse(input)
}

#[inline]
fn is_whitespace(c: u8) -> bool {
    b" \t\n\r\0\x0C".contains(&c)
}

#[inline]
fn is_delimiter(c: u8) -> bool {
    b"()<>[]{}/%".contains(&c)
}

#[inline]
fn is_regular(c: u8) -> bool {
    !is_whitespace(c) && !is_delimiter(c)
}

#[inline]
fn is_direct_literal_string(c: u8) -> bool {
    !b"()\\\r\n".contains(&c)
}

fn white_space(input: ParserInput) -> NomResult<()> {
    map(take_while(is_whitespace), |_| ()).parse(input)
}

/// White space and comments, as many as there are.
fn space(mut input: ParserInput) -> NomResult<()> {
    loop {
        let blanks = input.iter().take_while(|&&c| is_whitespace(c)).count();
        if blanks > 0 {
            input = &input[blanks..];
        } else if input.first() == Some(&b'%')
            && let Ok((rest, ())) = comment(input)
        {
            input = rest;
        } else {
            return Ok((input, ()));
        }
    }
}

/// The value of a run of ASCII digits, or `None` if it exceeds `u64`.
fn digits_value(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |value, &digit| {
        value.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    })
}

/// An optional `+` or `-` sign, and whether it was `-`.
fn sign(input: ParserInput) -> NomResult<bool> {
    match input.split_first() {
        Some((b'+', rest)) => Ok((rest, false)),
        Some((b'-', rest)) => Ok((rest, true)),
        _ => Ok((input, false)),
    }
}

fn integer(input: ParserInput) -> NomResult<i64> {
    let (i, (negative, digits)) = pair(sign, digit1).parse(input)?;

    let value = digits_value(digits).and_then(|magnitude| {
        if negative {
            0i64.checked_sub_unsigned(magnitude)
        } else {
            i64::try_from(magnitude).ok()
        }
    });
    convert_result(value.ok_or(()), i, ErrorKind::Digit)
}

fn real(input: ParserInput) -> NomResult<f32> {
    let (i, _) = pair(
        sign,
        alt((
            map((digit1, tag(&b"."[..]), digit0), |_| ()),
            map(pair(tag(&b"."[..]), digit1), |_| ()),
        )),
    )
    .parse(input)?;
    // Some producers write a minus sign inside the fraction, as in `0.00-4142502`. Like
    // pdf.js and Poppler, ignore it rather than splitting the number in two.
    let (i, fraction) = take_while(|c: u8| c == b'-' || c.is_ascii_digit()).parse(i)?;

    let float_input = &input[..input.len() - i.len()];
    let value = if fraction.contains(&b'-') {
        let (sign, rest) = float_input.split_at(1);
        let mut digits = sign.to_vec();
        digits.extend(rest.iter().filter(|&&c| c != b'-'));
        f32::from_str(str::from_utf8(&digits).unwrap())
    } else {
        f32::from_str(str::from_utf8(float_input).unwrap())
    };
    convert_result(value, i, ErrorKind::Digit)
}

/// The value of an ASCII hexadecimal digit.
#[inline]
fn hex_value(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|value| value as u8)
}

pub(crate) fn hex_char(input: ParserInput) -> NomResult<u8> {
    map_opt(take(2usize), |h: ParserInput| {
        Some((hex_value(h[0])? << 4) | hex_value(h[1])?)
    })
    .parse(input)
}

fn oct_char(input: ParserInput) -> NomResult<u8> {
    map_res(
        take_while_m_n(1, 3, AsChar::is_oct_digit),
        // Spec requires us to ignore any overflow.
        |x: ParserInput| u16::from_str_radix(str::from_utf8(x).unwrap(), 8).map(|o| o as u8),
    )
    .parse(input)
}

pub(crate) fn name(input: ParserInput) -> NomResult<Vec<u8>> {
    let (mut input, _) = tag(&b"/"[..]).parse(input)?;
    let mut bytes = Vec::new();
    loop {
        // Copy regular characters a run at a time, up to the next `#` or the end of the name.
        let run = input
            .iter()
            .position(|&c| c == b'#' || !is_regular(c))
            .unwrap_or(input.len());
        bytes.extend_from_slice(&input[..run]);
        input = &input[run..];
        // `#` and two hexadecimal digits stand for one byte; any other `#` ends the name.
        match input.split_first() {
            Some((b'#', escape)) => match hex_char(escape) {
                Ok((rest, byte)) => {
                    bytes.push(byte);
                    input = rest;
                }
                Err(_) => return Ok((input, bytes)),
            },
            _ => return Ok((input, bytes)),
        }
    }
}

fn escape_sequence(input: ParserInput) -> NomResult<Option<u8>> {
    preceded(
        tag(&b"\\"[..]),
        alt((
            map(oct_char, Some),
            map(eol, |_| None),
            map(tag(&b"n"[..]), |_| Some(b'\n')),
            map(tag(&b"r"[..]), |_| Some(b'\r')),
            map(tag(&b"t"[..]), |_| Some(b'\t')),
            map(tag(&b"b"[..]), |_| Some(b'\x08')),
            map(tag(&b"f"[..]), |_| Some(b'\x0C')),
            map(take(1usize), |c: ParserInput| Some(c[0])),
        )),
    )
    .parse(input)
}

enum InnerLiteralString<'a> {
    Direct(ParserInput<'a>),
    Escape(Option<u8>),
    Eol,
    Nested(Vec<u8>),
}

impl InnerLiteralString<'_> {
    fn push(&self, output: &mut Vec<u8>) {
        match self {
            InnerLiteralString::Direct(s) => output.extend_from_slice(s),
            InnerLiteralString::Eol => output.push(b'\n'),
            InnerLiteralString::Escape(e) => output.extend(e),
            InnerLiteralString::Nested(n) => output.extend_from_slice(n),
        }
    }
}

fn inner_literal_string(depth: usize) -> impl Fn(ParserInput) -> NomResult<Vec<u8>> {
    move |input| {
        fold_many0(
            alt((
                map(take_while1(is_direct_literal_string), InnerLiteralString::Direct),
                map(escape_sequence, InnerLiteralString::Escape),
                map(eol, |_| InnerLiteralString::Eol),
                map(nested_literal_string(depth), InnerLiteralString::Nested),
            )),
            Vec::new,
            |mut out: Vec<u8>, value| {
                value.push(&mut out);
                out
            },
        )
        .parse(input)
    }
}

fn nested_literal_string(depth: usize) -> impl Fn(ParserInput) -> NomResult<Vec<u8>> {
    move |input| {
        if depth == 0 {
            map(verify(tag(&b"too deep"[..]), |_: &[u8]| false), |_| vec![]).parse(input)
        } else {
            map(
                delimited(tag(&b"("[..]), inner_literal_string(depth - 1), tag(&b")"[..])),
                |mut content| {
                    content.insert(0, b'(');
                    content.push(b')');
                    content
                },
            )
            .parse(input)
        }
    }
}

fn literal_string(input: ParserInput) -> NomResult<Vec<u8>> {
    delimited(
        tag(&b"("[..]),
        inner_literal_string(crate::reader::MAX_BRACKET),
        tag(&b")"[..]),
    )
    .parse(input)
}

#[inline]
fn hex_digit(input: ParserInput) -> NomResult<u8> {
    map_opt(take(1usize), |c: ParserInput| hex_value(c[0])).parse(input)
}

fn hexadecimal_string(input: ParserInput) -> NomResult<Object> {
    map(
        delimited(
            tag(&b"<"[..]),
            terminated(
                fold_many0(
                    preceded(white_space, hex_digit),
                    || -> (Vec<u8>, bool) { (Vec::new(), false) },
                    |state, c| match state {
                        (mut out, false) => {
                            out.push(c << 4);
                            (out, true)
                        }
                        (mut out, true) => {
                            *out.last_mut().unwrap() |= c;
                            (out, false)
                        }
                    },
                ),
                white_space,
            ),
            tag(&b">"[..]),
        ),
        |(bytes, _)| Object::String(bytes, StringFormat::Hexadecimal),
    )
    .parse(input)
}

fn boolean(input: ParserInput) -> NomResult<Object> {
    alt((
        map(tag(&b"true"[..]), |_| Object::Boolean(true)),
        map(tag(&b"false"[..]), |_| Object::Boolean(false)),
    ))
    .parse(input)
}

fn null(input: ParserInput) -> NomResult<Object> {
    map(tag(&b"null"[..]), |_| Object::Null).parse(input)
}

fn array(depth: usize) -> impl Fn(ParserInput) -> NomResult<Vec<Object>> {
    move |input| {
        delimited(
            pair(tag(&b"["[..]), space),
            many0(_direct_object(depth)),
            tag(&b"]"[..]),
        )
        .parse(input)
    }
}

pub(crate) fn dictionary(input: ParserInput) -> NomResult<Dictionary> {
    _dictionary(crate::reader::MAX_NESTING_DEPTH)(input)
}

pub(crate) fn dictionary_with_reader<'a>(
    input: ParserInput<'a>, reader: &Reader,
) -> NomResult<'a, Dictionary> {
    match reader.parse_direct_object(input) {
        Ok((rest, Object::Dictionary(dictionary))) => Ok((rest, dictionary)),
        _ => Err(nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::TooLarge))),
    }
}

fn _dictionary(depth: usize) -> impl Fn(ParserInput) -> NomResult<Dictionary> {
    move |input| delimited(pair(tag(&b"<<"[..]), space), inner_dictionary(depth), tag(&b">>"[..])).parse(input)
}

fn inner_dictionary(depth: usize) -> impl Fn(ParserInput) -> NomResult<Dictionary> {
    move |input| {
        fold_many0(
            pair(terminated(name, space), _direct_object(depth)),
            Dictionary::new,
            |mut dict, (key, value)| {
                dict.set(key, value);
                dict
            },
        )
        .parse(input)
    }
}

pub(crate) fn dict_dup(input: ParserInput) -> NomResult<Dictionary> {
    delimited(
        (
            digit1,
            space1,
            tag(&b"dict"[..]),
            space1,
            tag(&b"dup"[..]),
            space1,
            tag(&b"begin"[..]),
            multispace1,
        ),
        fold_many0(
            terminated(
                pair(
                    terminated(name, space),
                    _direct_object(crate::reader::MAX_NESTING_DEPTH),
                ),
                pair(tag(&b"def"[..]), multispace1),
            ),
            Dictionary::new,
            |mut dict, (key, value)| {
                dict.set(key, value);
                dict
            },
        ),
        tag(&b"end"[..]),
    )
    .parse(input)
}

/// Recover the sole EOL-framed `endstream` immediately followed by `endobj`.
/// The caller must pass only bytes up to the current indirect-object boundary
/// so the scan cannot cross into a neighboring object.
fn recover_stream_length(input: ParserInput) -> Option<(ParserInput, ParserInput)> {
    const ENDSTREAM: &[u8] = b"endstream";
    let mut recovered = None;

    for (position, candidate) in input.windows(ENDSTREAM.len()).enumerate() {
        if candidate != ENDSTREAM {
            continue;
        }

        let data_end = if input[..position].ends_with(b"\r\n") {
            position - 2
        } else if input[..position].ends_with(b"\n") || input[..position].ends_with(b"\r") {
            position - 1
        } else {
            continue;
        };
        let after_endstream = &input[position + ENDSTREAM.len()..];
        let Ok((after_endobj, _)) = preceded(space, tag(&b"endobj"[..])).parse(after_endstream) else {
            continue;
        };
        if after_endobj.first().is_some_and(|&byte| !is_whitespace(byte)) {
            continue;
        }
        if recovered.is_some() {
            return None;
        }
        recovered = Some((after_endstream, &input[..data_end]));
    }

    recovered
}

/// The `stream` keyword and its end-of-line marker, which turn a dictionary into
/// the dictionary of a stream.
fn stream_keyword(input: ParserInput) -> NomResult<()> {
    map((space, tag(&b"stream"[..]), space0, eol), |_| ()).parse(input)
}

/// A stream whose dictionary `dict` starts `input`, with its data starting at `i`.
fn stream<'a>(
    input: ParserInput<'a>, i: ParserInput<'a>, dict: Dictionary, reader: &Reader,
    already_seen: &mut HashSet<ObjectId>, recover_length: bool, recovery_bound: Option<usize>,
) -> NomResult<'a, Object> {
    let length = dict.get(b"Length").and_then(|value| {
        if let Ok(id) = value.as_reference() {
            reader.get_object(id, already_seen).and_then(|value| value.as_i64())
        } else {
            value.as_i64()
        }
    });
    if reader.check_limits().is_err() {
        return Err(nom::Err::Failure(NomError::from_error_kind(i, ErrorKind::TooLarge)));
    }
    if let Ok(length) = length {
        if length < 0 {
            // artificial error kind is created to allow descriptive nom errors
            return Err(nom::Err::Failure(NomError::from_error_kind(i, ErrorKind::LengthValue)));
        }
        let Ok(length) = usize::try_from(length) else {
            return Err(nom::Err::Failure(NomError::from_error_kind(i, ErrorKind::LengthValue)));
        };
        match terminated(take(length), pair(opt(eol), tag(&b"endstream"[..]))).parse(i) {
            Ok((remaining, data)) => Ok((remaining, Object::Stream(Stream::new(dict, data.to_vec())))),
            Err(_) if recover_length && !reader.strict => {
                // The scan must not cross into a neighbouring object, so it stops at the
                // xref-derived bound: the first `i.len() - bound` bytes of `i`.
                let scan_end = recovery_bound.map_or(i.len(), |bound| i.len().saturating_sub(bound));
                let Some((remaining, data)) = recover_stream_length(&i[..scan_end]) else {
                    return Err(nom::Err::Failure(NomError::from_error_kind(i, ErrorKind::LengthValue)));
                };
                log::warn!(
                    "Stream Length is {length}, but the unambiguous object boundary gives {} bytes; using the recovered length.",
                    data.len()
                );
                Ok((remaining, Object::Stream(Stream::new(dict, data.to_vec()))))
            }
            Err(_) => Err(nom::Err::Failure(NomError::from_error_kind(i, ErrorKind::LengthValue))),
        }
    } else {
        // Return position relative to the start of the stream dictionary.
        Ok((i, Object::Stream(Stream::with_position(dict, input.len() - i.len()))))
    }
}

fn unsigned_int<I: TryFrom<u64>>(input: ParserInput) -> NomResult<I> {
    map_opt(digit1, |digits: ParserInput| {
        digits_value(digits).and_then(|value| I::try_from(value).ok())
    })
    .parse(input)
}

fn object_id(input: ParserInput) -> NomResult<ObjectId> {
    pair(terminated(unsigned_int, space), terminated(unsigned_int, space)).parse(input)
}

fn reference(input: ParserInput) -> NomResult<Object> {
    map(terminated(object_id, tag(&b"R"[..])), Object::Reference).parse(input)
}

fn _direct_objects(depth: usize) -> impl Fn(ParserInput) -> NomResult<Object> {
    // The first byte tells the kinds of object apart, so it selects the parsers to try.
    // An integer also matches the start of a reference or a real, so it is tried last.
    move |input| match input.first() {
        Some(b'n') => null(input),
        Some(b't' | b'f') => boolean(input),
        Some(b'0'..=b'9') => alt((reference, map(real, Object::Real), map(integer, Object::Integer))).parse(input),
        Some(b'+' | b'-' | b'.') => alt((map(real, Object::Real), map(integer, Object::Integer))).parse(input),
        Some(b'/') => map(name, Object::Name).parse(input),
        Some(b'(') => map(literal_string, Object::string_literal).parse(input),
        Some(b'<') => alt((hexadecimal_string, map(_dictionary(depth), Object::Dictionary))).parse(input),
        Some(b'[') => map(array(depth), Object::Array).parse(input),
        _ => Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::Alt))),
    }
}

fn _direct_object(depth: usize) -> impl Fn(ParserInput) -> NomResult<Object> {
    move |input| {
        if depth == 0 {
            return Err(nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::TooLarge)));
        }
        terminated(_direct_objects(depth - 1), space).parse(input)
    }
}

pub fn direct_object(input: ParserInput) -> Option<Object> {
    strip_nom(_direct_object(crate::reader::MAX_NESTING_DEPTH)(input))
}

fn object<'a>(
    input: ParserInput<'a>, reader: &Reader, already_seen: &mut HashSet<ObjectId>, recover_stream_length: bool,
    recovery_bound: Option<usize>,
) -> NomResult<'a, Object> {
    let (i, parsed) = reader.parse_direct_object(input)
        .map_err(|_| nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::Fail)))?;
    let (i, object) = if let Object::Dictionary(dict) = parsed {
        match stream_keyword(i) {
            Ok((data, ())) => stream(
                input,
                data,
                dict,
                reader,
                already_seen,
                recover_stream_length,
                recovery_bound,
            )?,
            Err(_) => (i, Object::Dictionary(dict)),
        }
    } else {
        (i, parsed)
    };
    let (i, ()) = space(i)?;
    Ok((i, object))
}

pub fn indirect_object(
    input: ParserInput, offset: usize, expected_id: Option<ObjectId>, reader: &Reader,
    already_seen: &mut HashSet<ObjectId>, recovery_bound: Option<usize>,
) -> crate::Result<(ObjectId, Object)> {
    // Every downstream slice is a suffix of `input`, so express the absolute
    // end offset as the maximum length a suffix may have.
    let recovery_bound = recovery_bound.map(|end| input.len().saturating_sub(end));
    let (id, mut object) = _indirect_object(
        input.take_from(offset),
        offset,
        expected_id,
        reader,
        already_seen,
        true,
        recovery_bound,
    )?;

    offset_stream(&mut object, offset);

    Ok((id, object))
}

fn _indirect_object<'a>(
    input: ParserInput<'a>, offset: usize, expected_id: Option<ObjectId>, reader: &Reader,
    already_seen: &mut HashSet<ObjectId>, recover_stream_length: bool, recovery_bound: Option<usize>,
) -> crate::Result<(ObjectId, Object)> {
    let (i, (_, object_id)) = terminated((space, object_id), pair(tag(&b"obj"[..]), space))
        .parse(input)
        .map_err(|_| Error::IndirectObject { offset })?;
    if let Some(expected_id) = expected_id
        && object_id != expected_id
    {
        return Err(crate::error::Error::ObjectIdMismatch);
    }

    let object_offset = input.len() - i.len();
    let parsed = terminated(
        |i: ParserInput<'a>| object(i, reader, already_seen, recover_stream_length, recovery_bound),
        (space, opt(tag(&b"endobj"[..])), space),
    )
    .parse(i);
    reader.check_limits()?;
    let (_, mut object) = parsed.map_err(|_| Error::IndirectObject { offset })?;

    offset_stream(&mut object, object_offset);

    Ok((object_id, object))
}

pub fn header(input: ParserInput, strict: bool) -> Option<String> {
    // Parse the version digits separately from trailing bytes: some generators put binary
    // markers on the header line. Strict mode rejects them, lenient mode skips them.
    let (_, (version_raw, trailing)) = delimited(
        tag(&b"%PDF-"[..]),
        pair(
            take_while(|c: u8| c.is_ascii_digit() || c == b'.'),
            take_while(|c: u8| !b"\r\n".contains(&c)),
        ),
        pair(eol, many0_count(comment)),
    )
    .parse(input)
    .ok()?;

    if strict && !trailing.is_empty() {
        return None;
    }

    let version = str::from_utf8(version_raw).ok()?.to_string();
    Some(version)
}

pub fn binary_mark(input: ParserInput) -> Option<Vec<u8>> {
    strip_nom(
        map_res(
            delimited(
                tag(&b"%"[..]),
                take_while(|c: u8| !b"\r\n".contains(&c)),
                pair(eol, many0_count(comment)),
            ),
            |v: ParserInput| Ok::<Vec<u8>, ()>(v.to_vec()),
        )
        .parse(input),
    )
}

/// Decode CrossReferenceTable
fn xref_with_reader<'a>(input: ParserInput<'a>, reader: &Reader) -> NomResult<'a, Xref> {
    // ISO 32000-1 s7.5.4 requires 20-byte entries ending in SP CR, SP LF or CR LF, but many
    // generators emit 19-byte entries ending in a bare LF, which qpdf, pikepdf, PDFium and
    // PDF.js accept. The conforming forms come first in the `alt` so a bare CR never matches
    // the CR of a CR LF and strands its LF.
    let xref_eol = move |i| {
        let conforming = alt((tag(&b" \r"[..]), tag(&b" \n"[..]), tag(&b"\r\n"[..])));
        if reader.strict {
            map(conforming, |_| ()).parse(i)
        } else {
            map(alt((conforming, tag(&b"\n"[..]), tag(&b"\r"[..]))), |_| ()).parse(i)
        }
    };
    let mut xref_entry = pair(
        separated_pair(unsigned_int, tag(&b" "[..]), unsigned_int::<u32>),
        delimited(tag(&b" "[..]), map(one_of("nf"), |k| k == 'n'), xref_eol),
    );
    let (mut input, _) = pair(tag(&b"xref"[..]), preceded(opt(tag(&b" "[..])), eol)).parse(input)?;
    let mut xref = Xref::new(0, XrefType::CrossReferenceTable);
    let mut sections = 0usize;
    loop {
        let header: NomResult<'a, (usize, usize)> = terminated(
            separated_pair(unsigned_int::<usize>, tag(&b" "[..]), unsigned_int::<usize>),
            pair(opt(tag(&b" "[..])), eol),
        ).parse(input);
        let Ok((remaining, (start, count))) = header else { break };
        if reader.check_xref_count(count).is_err() {
            return Err(nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::TooLarge)));
        }
        input = remaining;
        sections += 1;
        let mut index = 0usize;
        while let Ok((remaining, ((offset, generation), is_normal))) = xref_entry.parse(input) {
            if reader.reserve_xref_entries(1).is_err() {
                return Err(nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::TooLarge)));
            }
            if is_normal
                && let Ok(generation) = generation.try_into()
                && let Some(id) = start.checked_add(index).and_then(|id| u32::try_from(id).ok())
            {
                xref.insert(id, XrefEntry::Normal { offset, generation });
            }
            input = remaining;
            index = index.checked_add(1).ok_or_else(|| {
                nom::Err::Failure(NomError::from_error_kind(input, ErrorKind::TooLarge))
            })?;
        }
    }
    if sections == 0 {
        return Err(nom::Err::Error(NomError::from_error_kind(input, ErrorKind::Count)));
    }
    let (input, _) = space(input)?;
    Ok((input, xref))
}

#[cfg(test)]
fn xref(input: ParserInput, strict: bool) -> NomResult<Xref> {
    let reader = Reader::with_options(input, crate::LoadOptions { strict, ..Default::default() });
    xref_with_reader(input, &reader)
}

fn trailer<'a>(input: ParserInput<'a>, reader: &Reader) -> NomResult<'a, Dictionary> {
    delimited(
        pair(tag(&b"trailer"[..]), space),
        |input| dictionary_with_reader(input, reader),
        space,
    ).parse(input)
}

pub fn xref_and_trailer(input: ParserInput, reader: &Reader) -> crate::Result<(Xref, Dictionary)> {
    let xref_trailer = map(pair(|i| xref_with_reader(i, reader), |i| trailer(i, reader)), |(mut xref, trailer)| {
        xref.size = trailer
            .get(b"Size")
            .and_then(Object::as_i64)
            .map_err(|_| error::ParseError::InvalidTrailer)? as u32;
        Ok((xref, trailer))
    });
    let result = alt((
        xref_trailer,
        (|input| {
            _indirect_object(input, 0, None, reader, &mut HashSet::new(), false, None)
                .map(|(_, obj)| {
                    let res = match obj {
                        Object::Stream(stream) => reader.decode_xref_stream(stream),
                        _ => Err(crate::error::ParseError::InvalidXref.into()),
                    };
                    (input, res)
                })
                .map_err(|_| {
                    // artificial error kind is created to allow descriptive nom errors
                    nom::Err::Error(NomError::from_error_kind(input, ErrorKind::Fail))
                })
        }),
    ))
    .parse(input);
    reader.check_limits()?;
    result.map(|(_, o)| o).map_err(|_| error::ParseError::InvalidTrailer)?
}

pub fn xref_start(input: ParserInput) -> Option<i64> {
    strip_nom(
        delimited(
            pair(tag(&b"startxref"[..]), preceded(opt(tag(&b" "[..])), eol)),
            trim_spaces(integer),
            (eol, tag(&b"%%EOF"[..]), space),
        )
        .parse(input),
    )
}

fn trim_spaces<'a, O>(
    p: impl Parser<ParserInput<'a>, Output = O, Error = NomError<'a>>,
) -> impl Parser<ParserInput<'a>, Output = O, Error = NomError<'a>> {
    delimited(many0(tag(" ")), p, many0(tag(" ")))
}

// The following code create parser to parse content stream.

fn content_space(input: ParserInput) -> NomResult<()> {
    map(take_while(is_whitespace), |_| ()).parse(input)
}

fn operator(input: ParserInput) -> NomResult<String> {
    map_res(
        // Digits may follow the first character, as in the Type 3 glyph operators d0 and d1.
        verify(
            take_while1(|c: u8| c.is_ascii_alphanumeric() || b"*'\"".contains(&c)),
            |op: ParserInput| !op[0].is_ascii_digit(),
        ),
        |op: ParserInput| str::from_utf8(op).map(Into::into),
    )
    .parse(input)
}

fn operand(input: ParserInput) -> NomResult<Object> {
    terminated(
        alt((
            null,
            boolean,
            map(real, Object::Real),
            map(integer, Object::Integer),
            map(name, Object::Name),
            map(literal_string, Object::string_literal),
            hexadecimal_string,
            map(array(crate::reader::MAX_NESTING_DEPTH), Object::Array),
            map(dictionary, Object::Dictionary),
        )),
        content_space,
    )
    .parse(input)
}

fn operation(input: ParserInput) -> NomResult<Operation> {
    map(
        preceded(
            // A comment consumes its end-of-line marker, so also skip any
            // white space that follows it (e.g. an indented next line).
            many0(terminated(comment, content_space)),
            alt((inline_image, terminated(pair(many0(operand), operator), content_space))),
        ),
        |(operands, operator)| Operation { operator, operands },
    )
    .parse(input)
}

fn inline_image(input: ParserInput) -> NomResult<(Vec<Object>, String)> {
    preceded(pair(tag(&b"BI"[..]), content_space), cut(inline_image_impl)).parse(input)
}

/// The single white-space character between `ID` and the image data (ISO 32000-2, 8.9.7),
/// with a CR LF pair read as one end-of-line. White space after it is image data: a gray
/// level of 32 is a space byte.
fn inline_image_data_separator(input: ParserInput) -> NomResult<()> {
    map(opt(alt((eol, take_while_m_n(1, 1, is_whitespace)))), |_| ()).parse(input)
}

fn inline_image_impl(input: ParserInput) -> NomResult<(Vec<Object>, String)> {
    let (input, stream_dict) = inner_dictionary(crate::reader::MAX_NESTING_DEPTH).parse(input)?;
    let (input, _) = pair(tag(&b"ID"[..]), inline_image_data_separator).parse(input)?;
    match image_data_stream(input, stream_dict) {
        Ok((input, stream)) => {
            let (input, _) = (content_space, tag(&b"EI"[..]), content_space).parse(input)?;
            Ok((input, (vec![Object::Stream(stream)], String::from("BI"))))
        }
        Err(e) => {
            // Skip to EI marker so the rest of the content stream can still be parsed.
            log::warn!("Skipping unparseable inline image: {e}");
            let bytes = input;
            // EI must appear after whitespace to distinguish from data bytes.
            let ei_pos = bytes
                .windows(4)
                .position(|w| {
                    (w[0] == b' ' || w[0] == b'\n' || w[0] == b'\r')
                        && w[1] == b'E'
                        && w[2] == b'I'
                        && (w[3] == b' ' || w[3] == b'\n' || w[3] == b'\r')
                })
                .ok_or_else(|| {
                    let err: NomError = nom::error::Error::from_error_kind(input, ErrorKind::Fail);
                    nom::Err::Failure(err)
                })?;
            let (input, _) = take(ei_pos + 3).parse(input).map_err(|_: nom::Err<()>| {
                let err: NomError = nom::error::Error::from_error_kind(input, ErrorKind::Fail);
                nom::Err::Failure(err)
            })?;
            let (input, _) = content_space(input)?;
            Ok((input, (vec![], String::from("BI"))))
        }
    }
}

fn image_data_stream(input: ParserInput, stream_dict: Dictionary) -> crate::Result<(ParserInput, Stream)> {
    let (input, content) = image_data_bytes(input, &stream_dict)?;
    Ok((input, Stream::new(stream_dict, content.to_vec())))
}

// Keep image sizing and supported-filter decisions identical for both decoders.
fn image_data_bytes<'a>(input: ParserInput<'a>, stream_dict: &Dictionary) -> crate::Result<(ParserInput<'a>, &'a [u8])> {
    let get_abbr = |key_abbr: &[u8], key: &[u8]| stream_dict.get(key_abbr).or_else(|_| stream_dict.get(key));
    let invalid_size = || Error::InvalidInlineImage(String::from("image size out of range"));
    let get_size = |key_abbr: &[u8], key: &[u8]| -> crate::Result<usize> {
        usize::try_from(get_abbr(key_abbr, key)?.as_i64()?).map_err(|_| invalid_size())
    };
    let width = get_size(b"W", b"Width")?;
    let height = get_size(b"H", b"Height")?;
    let bpc = get_size(b"BPC", b"BitsPerComponent")?;
    let im = get_abbr(b"IM", b"ImageMask").and_then(|x| x.as_bool());
    let num_colors = match im {
        // If we have an image mask then we don't have a colorspace
        Ok(true) => 1,
        _ => match get_abbr(b"CS", b"ColorSpace")? {
            // An Indexed colour space is an array, and each sample is an index into its table.
            Object::Array(array) if matches!(array.first().map(Object::as_name), Some(Ok(b"Indexed" | b"I"))) => 1,
            colorspace => match colorspace.as_name()? {
                b"DeviceGray" | b"G" | b"Gray" => 1,
                b"DeviceRGB" | b"RGB" => 3,
                b"DeviceRGBA" | b"RGBA" => 4,
                b"DeviceCMYK" | b"CMYK" => 4,
                b"Pattern" => {
                    log::warn!("Pattern colorspace is not allowed in inline images");
                    return Err(Error::InvalidInlineImage(String::from(
                        "Pattern colorspace is not allowed in inline images",
                    )));
                }
                _ => {
                    log::warn!("Colorspace of inline image not recognized / not yet implemented");
                    return Err(Error::Unimplemented("inline image colorspaces"));
                }
            },
        },
    };

    let length = bpc
        .checked_mul(num_colors)
        .and_then(|bits_per_pixel| width.checked_mul(bits_per_pixel))
        .and_then(|row_bits| row_bits.div_ceil(8).checked_mul(height))
        .ok_or_else(invalid_size)?;

    let (input, content) = match get_abbr(b"F", b"Filter") {
        Err(_) => {
            // no decompression needed as no filter was applied
            take(length)
                .parse(input)
                .map_err(|_: nom::Err<()>| crate::error::ParseError::EndOfInput)?
        }
        Ok(Object::Name(_filter)) => {
            log::warn!("Filters for inline images are not yet implemented");
            return Err(Error::Unimplemented("filters for inline images"));
        }
        Ok(Object::Array(_filters)) => {
            log::warn!("Filters for inline images are not yet implemented");
            return Err(Error::Unimplemented("filters for inline images"));
        }
        Ok(obj) => {
            log::warn!("Filter must be either a Name or and Array.");
            return Err(Error::ObjectType {
                expected: "Name or Array",
                found: obj.enum_variant(),
            });
        }
    };
    Ok((input, content))
}

// The ordinary nom collectors cannot enforce a limit before growing an operand
// collection. This bounded path shares scalar grammar and inline-image sizing,
// but owns collection growth and flattens literal strings without recursion.
struct ContentBudget {
    objects: usize,
    bytes: usize,
    max_objects: usize,
    max_bytes: usize,
}

impl ContentBudget {
    fn limit(limit: usize) -> Error {
        crate::DecompressError::MemoryLimitExceeded { limit }.into()
    }

    fn node(&mut self) -> crate::Result<()> {
        self.objects = self.objects.checked_add(1)
            .filter(|&count| count <= self.max_objects)
            .ok_or_else(|| Self::limit(self.max_objects))?;
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> crate::Result<()> {
        self.bytes = self.bytes.checked_add(bytes)
            .filter(|&count| count <= self.max_bytes)
            .ok_or_else(|| Self::limit(self.max_bytes))?;
        Ok(())
    }

    fn reserve<T>(&mut self, values: &mut Vec<T>) -> crate::Result<()> {
        if values.len() == values.capacity() {
            let capacity = values.capacity().checked_mul(2)
                .map(|capacity| capacity.max(4))
                .ok_or_else(|| Self::limit(self.max_bytes))?;
            let extra = capacity - values.capacity();
            self.charge(extra.checked_mul(std::mem::size_of::<T>())
                .ok_or_else(|| Self::limit(self.max_bytes))?)?;
            values.try_reserve_exact(capacity - values.len())
                .map_err(|_| Self::limit(self.max_bytes))?;
        }
        Ok(())
    }

    fn push<T>(&mut self, values: &mut Vec<T>, value: T) -> crate::Result<()> {
        self.reserve(values)?;
        values.push(value);
        Ok(())
    }

    fn dictionary_entry(&mut self) -> crate::Result<()> {
        // IndexMap retains both ordered entries and a hash index. Charge slack
        // for both before insert, including growth of their backing allocations.
        self.charge(4 * std::mem::size_of::<(Vec<u8>, Object, usize, usize)>())
    }
}

fn bounded_parse<'a, T>(parsed: NomResult<'a, T>) -> crate::Result<(ParserInput<'a>, T)> {
    parsed.map_err(|_| error::ParseError::InvalidContentStream.into())
}

fn bounded_invalid<T>() -> crate::Result<T> {
    Err(error::ParseError::InvalidContentStream.into())
}

fn bounded_name<'a>(input: ParserInput<'a>, budget: &mut ContentBudget) -> crate::Result<(ParserInput<'a>, Vec<u8>)> {
    let mut rest = input.strip_prefix(b"/").ok_or(error::ParseError::InvalidContentStream)?;
    let mut length = 0usize;
    loop {
        let run = rest.iter().position(|&byte| byte == b'#' || !is_regular(byte)).unwrap_or(rest.len());
        length = length.checked_add(run).ok_or_else(|| ContentBudget::limit(budget.max_bytes))?;
        rest = &rest[run..];
        if let Some(escape) = rest.strip_prefix(b"#")
            && let Ok((tail, _)) = hex_char(escape)
        {
            length = length.checked_add(1).ok_or_else(|| ContentBudget::limit(budget.max_bytes))?;
            rest = tail;
        } else {
            break;
        }
    }
    // The existing name decoder grows geometrically; its first allocation has
    // room for at least eight bytes, even for a one-byte escaped name.
    if length != 0 {
        budget.charge(length.checked_mul(2).map(|bytes| bytes.max(8))
            .ok_or_else(|| ContentBudget::limit(budget.max_bytes))?)?;
    }
    bounded_parse(name(input))
}

fn bounded_literal<'a>(input: ParserInput<'a>, budget: &mut ContentBudget) -> crate::Result<(ParserInput<'a>, Vec<u8>)> {
    let mut rest = &input[1..];
    let mut depth = 0usize;
    let mut bytes = Vec::new();
    while let Some((&byte, tail)) = rest.split_first() {
        match byte {
            b'(' => {
                if depth == crate::reader::MAX_BRACKET {
                    return bounded_invalid();
                }
                depth += 1;
                budget.push(&mut bytes, byte)?;
                rest = tail;
            }
            b')' if depth == 0 => return Ok((tail, bytes)),
            b')' => {
                depth -= 1;
                budget.push(&mut bytes, byte)?;
                rest = tail;
            }
            b'\\' => {
                let (tail, escaped) = bounded_parse(escape_sequence(rest))?;
                if let Some(escaped) = escaped {
                    budget.push(&mut bytes, escaped)?;
                }
                rest = tail;
            }
            b'\r' | b'\n' => {
                let (tail, _) = bounded_parse(eol(rest))?;
                budget.push(&mut bytes, b'\n')?;
                rest = tail;
            }
            _ => {
                budget.push(&mut bytes, byte)?;
                rest = tail;
            }
        }
    }
    bounded_invalid()
}

fn bounded_hexadecimal<'a>(
    input: ParserInput<'a>, budget: &mut ContentBudget,
) -> crate::Result<(ParserInput<'a>, Object)> {
    let mut rest = &input[1..];
    let mut bytes = Vec::new();
    let mut high = true;
    loop {
        rest = bounded_parse(white_space(rest))?.0;
        if let Some(tail) = rest.strip_prefix(b">") {
            return Ok((tail, Object::String(bytes, StringFormat::Hexadecimal)));
        }
        let (tail, digit) = bounded_parse(hex_digit(rest))?;
        if high {
            budget.push(&mut bytes, digit << 4)?;
        } else if let Some(last) = bytes.last_mut() {
            *last |= digit;
        }
        high = !high;
        rest = tail;
    }
}

fn bounded_dictionary<'a>(
    mut input: ParserInput<'a>, budget: &mut ContentBudget, depth: usize, inline: bool,
) -> crate::Result<(ParserInput<'a>, Dictionary)> {
    let mut dictionary = Dictionary::new();
    loop {
        if !inline && let Some(rest) = input.strip_prefix(b">>") {
            return Ok((rest, dictionary));
        }
        if inline && input.starts_with(b"ID") {
            return Ok((input, dictionary));
        }
        budget.node()?; // Dictionary key names are syntax nodes too.
        budget.dictionary_entry()?;
        let (rest, key) = bounded_name(input, budget)?;
        let rest = bounded_parse(space(rest))?.0;
        let (rest, value) = bounded_object(rest, budget, depth, true)?;
        dictionary.set(key, value);
        input = bounded_parse(space(rest))?.0;
    }
}

fn bounded_object<'a>(
    input: ParserInput<'a>, budget: &mut ContentBudget, depth: usize, direct: bool,
) -> crate::Result<(ParserInput<'a>, Object)> {
    if depth == 0 {
        return bounded_invalid();
    }
    budget.node()?;
    match input.first() {
        Some(b'[') => {
            let mut rest = bounded_parse(space(&input[1..]))?.0;
            let mut values = Vec::new();
            loop {
                if let Some(tail) = rest.strip_prefix(b"]") {
                    return Ok((tail, Object::Array(values)));
                }
                let (tail, value) = bounded_object(rest, budget, depth - 1, true)?;
                budget.push(&mut values, value)?;
                rest = bounded_parse(space(tail))?.0;
            }
        }
        Some(b'<') if input.starts_with(b"<<") => {
            let rest = bounded_parse(space(&input[2..]))?.0;
            let (rest, dictionary) = bounded_dictionary(rest, budget, depth - 1, false)?;
            Ok((rest, Object::Dictionary(dictionary)))
        }
        Some(b'<') => bounded_hexadecimal(input, budget),
        Some(b'(') => {
            let (rest, bytes) = bounded_literal(input, budget)?;
            Ok((rest, Object::string_literal(bytes)))
        }
        Some(b'/') => {
            let (rest, bytes) = bounded_name(input, budget)?;
            Ok((rest, Object::Name(bytes)))
        }
        Some(b'n') => bounded_parse(null(input)),
        Some(b't' | b'f') => bounded_parse(boolean(input)),
        Some(b'0'..=b'9') if direct && reference(input).is_ok() => bounded_parse(reference(input)),
        Some(b'0'..=b'9' | b'+' | b'-' | b'.') => {
            // Only the tolerant fractional-minus branch of real() allocates.
            // Bound its temporary copy before calling the shared scalar parser.
            let token = input.iter().take_while(|&&byte| byte.is_ascii_digit() || b"+-.".contains(&byte)).count();
            if input[..token].get(1..).is_some_and(|fraction| fraction.contains(&b'-')) {
                budget.charge(token.checked_mul(2).map(|bytes| bytes.max(8))
                    .ok_or_else(|| ContentBudget::limit(budget.max_bytes))?)?;
            }
            bounded_parse(alt((map(real, Object::Real), map(integer, Object::Integer))).parse(input))
        }
        _ => bounded_invalid(),
    }
}

pub(crate) fn reader_direct_object<'a>(
    input: ParserInput<'a>, max_objects: Option<usize>,
) -> (crate::Result<(ParserInput<'a>, Object)>, usize) {
    let Some(max_objects) = max_objects else {
        let parsed = terminated(_direct_objects(crate::reader::MAX_NESTING_DEPTH), space).parse(input);
        return (bounded_parse(parsed), 0);
    };
    // Raw syntax bytes remain bounded by the source input. Only decoded streams
    // consume the loader's separate cumulative decompressed-byte budget.
    let mut budget = ContentBudget {
        objects: 0, bytes: 0, max_objects, max_bytes: usize::MAX,
    };
    let parsed = bounded_object(input, &mut budget, crate::reader::MAX_NESTING_DEPTH, true)
        .and_then(|(rest, object)| {
            bounded_parse(space(rest)).map(|(rest, ())| (rest, object))
        });
    (parsed, budget.objects)
}

pub(crate) fn content_bounded(
    mut input: ParserInput<'_>, max_objects: usize, max_decoded_bytes: usize,
) -> crate::Result<(Content<Vec<Operation>>, usize, usize)> {
    let mut budget = ContentBudget { objects: 0, bytes: 0, max_objects, max_bytes: max_decoded_bytes };
    let mut operations = Vec::new();
    loop {
        input = bounded_parse(space(input))?.0;
        if input.is_empty() {
            return Ok((Content { operations }, budget.objects, budget.bytes));
        }
        budget.node()?;
        budget.reserve(&mut operations)?;
        let mut operands = Vec::new();
        let operator;
        if let Some(rest) = input.strip_prefix(b"BI") {
            let rest = bounded_parse(content_space(rest))?.0;
            let (rest, dictionary) = bounded_dictionary(rest, &mut budget, crate::reader::MAX_NESTING_DEPTH, true)?;
            let rest = rest.strip_prefix(b"ID").ok_or(error::ParseError::InvalidContentStream)?;
            let rest = bounded_parse(inline_image_data_separator(rest))?.0;
            let (rest, bytes) = image_data_bytes(rest, &dictionary)?;
            // Stream::new adds an implicit /Length entry. Charge it before that
            // insertion, and before copying the image's potentially large leaf.
            budget.node()?;
            budget.node()?;
            budget.node()?;
            budget.dictionary_entry()?;
            budget.charge(b"Length".len())?;
            budget.charge(bytes.len())?;
            i64::try_from(bytes.len()).map_err(|_| error::ParseError::InvalidContentStream)?;
            budget.reserve(&mut operands)?;
            let stream = Stream::new(dictionary, bytes.to_vec());
            operands.push(Object::Stream(stream));
            input = bounded_parse(content_space(rest))?.0;
            input = input.strip_prefix(b"EI").ok_or(error::ParseError::InvalidContentStream)?;
            budget.charge(2)?;
            operator = String::from("BI");
        } else {
            loop {
                let is_operand = matches!(input.first(), Some(b'/' | b'(' | b'<' | b'[' | b'0'..=b'9' | b'+' | b'-' | b'.'))
                    || input.starts_with(b"null") || input.starts_with(b"true") || input.starts_with(b"false");
                if !is_operand {
                    break;
                }
                // operand() gives its outer array/dictionary one extra level
                // before the nested _direct_object depth limit starts.
                let depth = crate::reader::MAX_NESTING_DEPTH.saturating_add(1);
                let (rest, value) = bounded_object(input, &mut budget, depth, false)?;
                budget.push(&mut operands, value)?;
                input = bounded_parse(content_space(rest))?.0;
            }
            let length = input.iter().take_while(|&&byte| byte.is_ascii_alphanumeric() || b"*'\"".contains(&byte)).count();
            budget.charge(length)?;
            let (rest, parsed_operator) = bounded_parse(self::operator(input))?;
            input = rest;
            operator = parsed_operator;
        }
        operations.push(Operation { operator, operands });
    }
}

fn _content(input: ParserInput) -> NomResult<Content<Vec<Operation>>> {
    delimited(
        content_space,
        map(many0(operation), |operations| Content { operations }),
        many0(terminated(comment, content_space)),
    )
    .parse(input)
}

pub fn content(input: ParserInput) -> Option<Content<Vec<Operation>>> {
    strip_nom(_content.parse(input))
}

/// The operations of a content stream, decoded one at a time with the grammar of
/// [`content`].
///
/// Yields exactly the operations `content` collects, in order, then an error where
/// `content` fails, so the operations of a large stream need not all be held at once.
pub struct ContentOperations<'a> {
    input: ParserInput<'a>,
    started: bool,
    finished: bool,
}

impl<'a> ContentOperations<'a> {
    pub(crate) fn new(input: ParserInput<'a>) -> Self {
        ContentOperations {
            input,
            started: false,
            finished: false,
        }
    }

    fn fail(&mut self) -> Option<crate::Result<Operation>> {
        self.finished = true;
        Some(Err(error::ParseError::InvalidContentStream.into()))
    }
}

impl Iterator for ContentOperations<'_> {
    type Item = crate::Result<Operation>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if !self.started {
            self.started = true;
            match content_space(self.input) {
                Ok((input, ())) => self.input = input,
                Err(_) => return self.fail(),
            }
        }
        let len = self.input.len();
        match operation(self.input) {
            // `many0` fails when its parser succeeds without consuming input.
            Ok((input, _)) if input.len() == len => self.fail(),
            Ok((input, operation)) => {
                self.input = input;
                Some(Ok(operation))
            }
            // `many0` stops at a recoverable error, and `content` ignores the rest.
            Err(nom::Err::Error(_)) => {
                self.finished = true;
                None
            }
            Err(_) => self.fail(),
        }
    }
}

pub fn content_strict(input: ParserInput) -> Result<Content<Vec<Operation>>, error::ParseError> {
    let (rest, content) = _content
        .parse(input)
        .map_err(|_| error::ParseError::InvalidContentStream)?;
    if !rest.is_empty() {
        return Err(error::ParseError::InvalidContentStream);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_span(s: &'_ [u8]) -> ParserInput<'_> {
        s
    }

    fn tstrip<O>(r: NomResult<O>) -> Option<O> {
        r.ok().and_then(|(i, o)| if !i.is_empty() { None } else { Some(o) })
    }

    #[test]
    fn content_operations_match_content() {
        let streams: [&[u8]; 6] = [
            b"",
            b"q 1 0 0 1 72 720 cm BT /F1 12 Tf [(A) -120 (B)] TJ ET Q",
            b"  % leading comment\n0 0 m 10 10 l S\n% trailing comment\n",
            b"BT /F1 12 Tf (text) Tj ET\n) unparsable trailing input is ignored",
            b"BI /W 1 /H 1 /BPC 8 /CS /G ID X EI 0 0 m",
            b"/P <</MCID 0>> BDC BT (marked) Tj ET EMC",
        ];
        for stream in streams {
            let expected = content(test_span(stream)).expect("content decodes");
            let operations = ContentOperations::new(test_span(stream))
                .collect::<crate::Result<Vec<_>>>()
                .expect("operations decode");
            assert_eq!(
                format!("{:?}", operations),
                format!("{:?}", expected.operations),
                "stream: {:?}",
                String::from_utf8_lossy(stream)
            );
        }
    }

    #[test]
    fn content_operations_fail_where_content_fails() {
        // Without EI the inline image cannot be skipped, so the whole decode fails.
        let stream = test_span(b"BT (before) Tj ET\nBI /W 1 /H 1 /BPC 8 /CS /G ID X\nBT (after) Tj ET");
        assert!(content(stream).is_none());

        let mut operations = ContentOperations::new(stream);
        for operator in ["BT", "Tj", "ET"] {
            assert_eq!(operations.next().unwrap().unwrap().operator, operator);
        }
        assert!(matches!(
            operations.next(),
            Some(Err(Error::Parse(error::ParseError::InvalidContentStream)))
        ));
        assert!(operations.next().is_none());
    }

    #[test]
    fn parse_real_number() {
        let real = |i| tstrip(real(i));

        assert_eq!(real(test_span(b"0.12")), Some(0.12));
        assert_eq!(real(test_span(b"-.12")), Some(-0.12));
        assert_eq!(real(test_span(b"10.")), Some(10.0));
        // A minus sign inside the fraction is ignored.
        assert_eq!(real(test_span(b"0.00-4142502")), Some(0.004142502));
        assert_eq!(real(test_span(b"-1.5-5")), Some(-1.55));
    }

    #[test]
    fn parse_string() {
        let literal_string = |i| tstrip(literal_string(i));

        let data = vec![
            ("()", ""),
            ("(text())", "text()"),
            ("(text\r\n\\\\(nested\\t\\b\\f))", "text\n\\(nested\t\x08\x0C)"),
            // An unescaped end-of-line marker of any kind reads as a single line feed.
            ("(a\rb\nc\r\n\r\nd\n\re)", "a\nb\nc\n\nd\n\ne"),
            ("(text\\0\\53\\053\\0053)", "text\0++\x053"),
            ("(text line\\\n())", "text line()"),
        ];

        for (input, expected) in data {
            assert_eq!(
                literal_string(test_span(input.as_bytes())),
                Some(expected.as_bytes().to_vec()),
                "input: {:?} output: {:?}",
                input,
                expected,
            );
        }
    }

    #[test]
    fn parse_name() {
        let (text, expected) = (b"/ABC#5f", b"ABC\x5F");
        let result = tstrip(name(test_span(text)));
        assert_eq!(result, Some(expected.to_vec()));

        let (text, expected) = (b"/#cb#ce#cc#e5", b"\xcb\xce\xcc\xe5");
        let result = tstrip(name(test_span(text)));
        assert_eq!(result, Some(expected.to_vec()));
    }

    #[test]
    /// Run `cargo test -- --nocapture` to see output
    fn parse_content() {
        let stream = b"
2 J
BT
/F1 12 Tf
0 Tc
0 Tw
72.5 712 TD
[(Unencoded streams can be read easily) 65 (,) ] TJ
0 -14 TD
[(b) 20 (ut generally tak) 10 (e more space than \\311)] TJ
T* (encoded streams.) Tj
		";
        let content = tstrip(_content(test_span(stream)));
        assert!(content.is_some());
    }

    #[test]
    fn hex_partial() {
        // Example from PDF specification.
        let out = tstrip(hexadecimal_string(test_span(b"<901FA>")));

        match out {
            Some(Object::String(s, _)) => assert_eq!(s, b"\x90\x1F\xA0".to_vec()),
            _ => panic!("unexpected {:?}", out),
        }
    }

    #[test]
    fn hex_separated() {
        let out = tstrip(hexadecimal_string(test_span(b"<9 01F A>")));

        match out {
            Some(Object::String(s, _)) => assert_eq!(s, b"\x90\x1F\xA0".to_vec()),
            _ => panic!("unexpected {:?}", out),
        }
    }

    #[test]
    fn big_generation_value() {
        let input = b"xref
0 1
0000000000 65536 f\x20
0 16
0000000000 65535 f\x20
0000153238 00000 n\x20
0000000019 00000 n\x20
0000000313 00000 n\x20
0000000333 00000 n\x20
0000145531 00000 n\x20
0000153407 00000 n\x20
0000145554 00000 n\x20
0000152303 00000 n\x20
0000152324 00000 n\x20
0000152514 00000 n\x20
0000152880 00000 n\x20
0000153106 00000 n\x20
0000153139 00000 n\x20
0000153532 00000 n\x20
0000153629 00000 n\x20
trailer
<</Size 16/Root 14 0 R
/Info 15 0 R
/ID [ <9DDC4B621B3F485FF5ED0F57D00A028F>
<9DDC4B621B3F485FF5ED0F57D00A028F> ]
/DocChecksum /2BCC3C7DE26E6BF3573E4A6E8362221F
>>
startxref
153804\x20
%%EOF
";
        match xref(test_span(input), false) {
            Ok((_, re)) => assert_eq!(re.entries.len(), 15),
            Err(err) => panic!("unexpected {:?}", err),
        }
    }

    #[test]
    fn space_in_startxref_number() {
        let input = b"startxref
153804\x20
%%EOF
";
        match xref_start(test_span(input)) {
            Some(num) => assert_eq!(num, 153804),
            None => panic!("could not parse number in startxref"),
        }
    }

    #[test]
    fn header_standard() {
        // Standard header with proper EOL
        let input = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n";
        assert_eq!(header(test_span(input), false), Some("1.7".to_string()));
    }

    #[test]
    fn header_with_binary_bytes_on_same_line() {
        // Some generators (e.g. ImageMill) place binary marker bytes on the
        // header line without a separating newline or '%' prefix.
        let input = b"%PDF-1.3 \xb0\x9f\x92\x9c\x9f\xd4\xe0\xce\xd0\xd0\xd0\r1 0 obj\r";
        assert_eq!(header(test_span(input), false), Some("1.3".to_string()));
    }

    #[test]
    fn header_with_binary_bytes_strict_rejects() {
        // In strict mode, binary bytes on the header line should cause a
        // parse failure (the raw bytes are not valid UTF-8).
        let input = b"%PDF-1.3 \xb0\x9f\x92\x9c\x9f\xd4\xe0\xce\xd0\xd0\xd0\r1 0 obj\r";
        assert_eq!(header(test_span(input), true), None);
    }

    #[test]
    fn header_cr_line_ending() {
        // CR-only line ending (common in older PDFs)
        let input = b"%PDF-1.3\r%\xe2\xe3\xcf\xd3\r";
        assert_eq!(header(test_span(input), false), Some("1.3".to_string()));
    }

    #[test]
    fn header_crlf_line_ending() {
        // CRLF line ending (common on Windows-generated PDFs)
        let input = b"%PDF-1.7\r\n%\xe2\xe3\xcf\xd3\r\n";
        assert_eq!(header(test_span(input), false), Some("1.7".to_string()));
    }

    #[test]
    fn header_pdf_2_0() {
        let input = b"%PDF-2.0\n%\xe2\xe3\xcf\xd3\n";
        assert_eq!(header(test_span(input), false), Some("2.0".to_string()));
    }

    #[test]
    fn content_with_comments() {
        // It should be processed as usual but ignoring the comments
        let input = b"0.5 0.5 0.5 setrgbcolor
% This is a comment
100 100 moveto
(Hello, world!) show
% Another comment
";
        let out = content(test_span(input)).unwrap();
        let out_strict = content_strict(test_span(input)).unwrap();
        assert_eq!(out.operations.len(), out_strict.operations.len());
        assert_eq!(out.operations.len(), 3);
    }

    #[test]
    fn content_with_comment_followed_by_indented_line() {
        // A comment is a single whitespace character (ISO 32000-2, 7.2.4), so an indented
        // line right after one must not stop the parser (issue #535).
        let input = b"BT /F1 24 Tf
% comment
  100 100 Td (Hello World) Tj ET";
        let out = content(test_span(input)).unwrap();
        let out_strict = content_strict(test_span(input)).unwrap();
        assert_eq!(out.operations.len(), out_strict.operations.len());
        let ops: Vec<&str> = out.operations.iter().map(|o| o.operator.as_str()).collect();
        assert_eq!(ops, vec!["BT", "Tf", "Td", "Tj", "ET"]);
    }

    #[test]
    fn inline_image_unknown_colorspace_skipped() {
        // Inline image with an unrecognized colorspace ("ICCBased" is not handled).
        // The parser should skip it and still parse the surrounding operations.
        let input = b"q 100 100 moveto
BI /W 2 /H 2 /CS /ICCBased /BPC 8
ID
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
EI
(Hello) Tj Q";
        let out = content(test_span(input)).unwrap();
        // Should have: q, moveto, BI (skipped), Tj, Q = 5 operations
        let ops: Vec<&str> = out.operations.iter().map(|o| o.operator.as_str()).collect();
        assert!(ops.contains(&"q"), "missing q, got: {:?}", ops);
        assert!(ops.contains(&"Tj"), "missing Tj, got: {:?}", ops);
        assert!(ops.contains(&"Q"), "missing Q, got: {:?}", ops);
    }

    #[test]
    fn inline_image_with_invalid_dimensions_skipped() {
        // Negative dimensions or a byte count that doesn't fit in usize must not overflow.
        for dims in [
            &b"/W -1 /H 1 /BPC 8"[..],
            b"/W 4294967296 /H 4294967296 /BPC 8",
            b"/W 1 /H 1 /BPC 9223372036854775807",
        ] {
            let mut input = b"q BI ".to_vec();
            input.extend_from_slice(dims);
            input.extend_from_slice(b" /CS /DeviceRGB ID \x00\x00\x00 EI (Hello) Tj Q");
            let out = content(test_span(&input)).unwrap();
            let ops: Vec<&str> = out.operations.iter().map(|o| o.operator.as_str()).collect();
            assert_eq!(ops, vec!["q", "BI", "Tj", "Q"]);
            assert!(out.operations[1].operands.is_empty());
        }
    }

    #[test]
    fn inline_image() {
        let _ = env_logger::try_init();
        let input = b"BI /W 4 /H 4 /CS /RGB /BPC 8
ID
00000z0z00zzz00z0zzz0zzzEI aazazaazzzaazazzzazzz
EI";
        let out = super::inline_image(test_span(input)).unwrap().1;
        assert_eq!(&out.1, "BI");
        assert_eq!(
            &out.0[0].as_stream().unwrap().content,
            b"00000z0z00zzz00z0zzz0zzzEI aazazaazzzaazazzzazzz"
        )
    }

    #[test]
    fn inline_image_abbreviated_color_spaces() {
        // 2x1 images using the abbreviated colour space names allowed in inline images.
        for (color_space, data) in [
            (&b"/G"[..], &b"\x00\xff"[..]),
            (b"/RGB", b"\x00\x00\x00\xff\xff\xff"),
            (b"/CMYK", b"\x00\x00\x00\x00\xff\xff\xff\xff"),
            (b"[/I /RGB 1 <000000FFFFFF>]", b"\x00\x01"),
            (b"[/Indexed /DeviceRGB 1 <000000FFFFFF>]", b"\x00\x01"),
        ] {
            let mut input = b"q BI /W 2 /H 1 /BPC 8 /CS ".to_vec();
            input.extend_from_slice(color_space);
            input.extend_from_slice(b" ID ");
            input.extend_from_slice(data);
            input.extend_from_slice(b" EI Q");
            let out = content(test_span(&input)).unwrap();
            let ops: Vec<&str> = out.operations.iter().map(|o| o.operator.as_str()).collect();
            assert_eq!(ops, vec!["q", "BI", "Q"]);
            let image = out.operations[1].operands[0].as_stream().unwrap();
            assert_eq!(image.content, data);
        }
    }

    #[test]
    fn inline_image_data_starting_with_white_space() {
        // A 3x1 gray image whose three pixels have level 32, i.e. space bytes. Only the
        // first white-space character after ID separates it from the data.
        let input = b"q\rBI\r/CS/DeviceGray/W 3/H 1/BPC 8\rID\r   \nEI\rQ\r";
        let out = content_strict(test_span(input)).unwrap();
        let ops: Vec<&str> = out.operations.iter().map(|o| o.operator.as_str()).collect();
        assert_eq!(ops, vec!["q", "BI", "Q"]);
        assert_eq!(&out.operations[1].operands[0].as_stream().unwrap().content, b"   ");
    }

    #[test]
    fn inline_image_data_after_crlf() {
        // A CR LF after ID is one end-of-line, so the data starts after the LF.
        let input = b"BI /CS /DeviceGray /W 2 /H 1 /BPC 8 ID\r\n\n\x80\nEI";
        let out = super::inline_image(test_span(input)).unwrap().1;
        assert_eq!(&out.0[0].as_stream().unwrap().content, b"\n\x80");
    }

    #[test]
    fn xref_trailing_space_after_keyword() {
        // Some PDF generators emit "xref \n" with a trailing space.
        let input = b"xref \n0 3\n0000000000 65535 f \n0000000017 00000 n \n0000000081 00000 n \ntrailer\n<</Size 3/Root 1 0 R>>\nstartxref\n175\n%%EOF\n";
        match xref(test_span(input), false) {
            Ok((_, re)) => assert_eq!(re.entries.len(), 2),
            Err(err) => panic!("xref with trailing space should parse: {:?}", err),
        }
    }

    #[test]
    fn xref_entries_with_bare_eol_terminator() {
        // 19-byte entries with a bare "\n" terminator are non-conforming but accepted by
        // qpdf, pikepdf, PDFium and PDF.js, so lenient parsing accepts them too.
        for (name, input) in [
            (
                "bare LF",
                &b"xref\n0 3\n0000000000 65535 f\n0000000017 00000 n\n0000000081 00000 n\ntrailer\n<</Size 3/Root 1 0 R>>\n"[..],
            ),
            (
                "bare CR",
                &b"xref\n0 3\n0000000000 65535 f\r0000000017 00000 n\r0000000081 00000 n\rtrailer\n<</Size 3/Root 1 0 R>>\n"[..],
            ),
        ] {
            match xref(test_span(input), false) {
                Ok((_, re)) => assert_eq!(re.entries.len(), 2, "{name} should yield both normal entries"),
                Err(err) => panic!("19-byte entries ({name}) should parse when lenient: {err:?}"),
            }
        }
    }

    #[test]
    fn xref_entries_with_bare_eol_rejected_when_strict() {
        // Rejection is indirect: the entries are not recognised, leaving an empty section
        // whose unconsumed lines then displace `trailer`.
        let input =
            b"xref\n0 3\n0000000000 65535 f\n0000000017 00000 n\n0000000081 00000 n\ntrailer\n<</Size 3/Root 1 0 R>>\n";
        if let Ok((_, re)) = xref(test_span(input), true) {
            assert_eq!(re.entries.len(), 0, "strict must not accept 19-byte entries");
        }

        // The 20-byte build of the same document is the control: it must load in both
        // modes, so any strict rejection is attributable to the terminator alone.
        let load = |bytes: &[u8], strict: bool| {
            crate::Document::load_mem_with_options(
                bytes,
                crate::LoadOptions {
                    strict,
                    ..Default::default()
                },
            )
        };

        for (name, term, strict_should_load) in [("19-byte", "\n", false), ("20-byte", " \n", true)] {
            let header = "%PDF-1.7\n";
            let obj1 = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
            let obj2 = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
            let obj3 = "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n";
            let o1 = header.len();
            let o2 = o1 + obj1.len();
            let o3 = o2 + obj2.len();
            let body = format!("{header}{obj1}{obj2}{obj3}");
            let xref_pos = body.len();
            let doc = format!(
                "{body}xref\n0 4\n0000000000 65535 f{term}{o1:010} 00000 n{term}{o2:010} 00000 n{term}\
                 {o3:010} 00000 n{term}trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n"
            );

            assert!(
                load(doc.as_bytes(), false).is_ok(),
                "{name} entries should load when lenient"
            );
            assert_eq!(
                load(doc.as_bytes(), true).is_ok(),
                strict_should_load,
                "{name} entries under strict parsing"
            );
        }
    }

    #[test]
    fn xref_entries_with_conforming_terminators() {
        // The three 20-byte terminators of s7.5.4 must keep parsing in both modes.
        for (name, input) in [
            (
                "SP LF",
                &b"xref\n0 3\n0000000000 65535 f \n0000000017 00000 n \n0000000081 00000 n \ntrailer\n<</Size 3/Root 1 0 R>>\n"[..],
            ),
            (
                "SP CR",
                &b"xref\n0 3\n0000000000 65535 f \r0000000017 00000 n \r0000000081 00000 n \rtrailer\n<</Size 3/Root 1 0 R>>\n"[..],
            ),
            (
                "CR LF",
                &b"xref\n0 3\n0000000000 65535 f\r\n0000000017 00000 n\r\n0000000081 00000 n\r\ntrailer\n<</Size 3/Root 1 0 R>>\n"[..],
            ),
        ] {
            for strict in [false, true] {
                match xref(test_span(input), strict) {
                    Ok((_, re)) => assert_eq!(re.entries.len(), 2, "{name} (strict={strict}) lost an entry"),
                    Err(err) => panic!("conforming {name} entries should parse (strict={strict}): {err:?}"),
                }
            }
        }
    }

    #[test]
    fn xref_subsection_start_near_usize_max_is_skipped() {
        // A start of usize::MAX made `start + index` overflow: a panic where overflow checks
        // are on, and a silent wrap to object 0 where they are not.
        let input = &b"xref\n18446744073709551615 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<</Size 2/Root 1 0 R>>\n"[..];
        for strict in [false, true] {
            match xref(test_span(input), strict) {
                Ok((_, re)) => assert!(
                    re.entries.is_empty(),
                    "unrepresentable object number was inserted (strict={strict}): {:?}",
                    re.entries
                ),
                Err(err) => panic!("xref should still parse (strict={strict}): {err:?}"),
            }
        }
    }

    #[test]
    fn xref_subsection_start_beyond_u32_does_not_displace_entries() {
        // A start above u32::MAX truncated into a valid-looking number (4294967297 becomes 1),
        // overwriting a legitimate entry. No overflow occurs, so a checked add alone misses it.
        let input = &b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n4294967297 1\n0000000999 00000 n \ntrailer\n<</Size 2/Root 1 0 R>>\n"[..];
        for strict in [false, true] {
            match xref(test_span(input), strict) {
                Ok((_, re)) => {
                    assert_eq!(
                        re.entries.len(),
                        1,
                        "(strict={strict}) unexpected entries: {:?}",
                        re.entries
                    );
                    assert!(
                        matches!(
                            re.get(1),
                            Some(XrefEntry::Normal {
                                offset: 9,
                                generation: 0
                            })
                        ),
                        "entry for object 1 was displaced (strict={strict}): {:?}",
                        re.get(1)
                    );
                }
                Err(err) => panic!("xref should still parse (strict={strict}): {err:?}"),
            }
        }
    }

    #[test]
    fn startxref_trailing_space_after_keyword() {
        // Some PDF generators emit "startxref \n" with a trailing space.
        let input = b"startxref \n135738\n%%EOF\n";
        match xref_start(test_span(input)) {
            Some(num) => assert_eq!(num, 135738),
            None => panic!("startxref with trailing space should parse"),
        }
    }

    #[test]
    fn content_silently_truncates_corrupted_data() {
        // Corrupted data with unterminated string literal
        let data = b"q 1 0 0 1 10 10 cm (corrupted Q";

        let content = content(data).unwrap();

        // Operations before the corruption returned without an error.
        // Trailing Q was silently dropped.
        assert_eq!(content.operations.len(), 2);
        assert_eq!(content.operations[0].operator, "q");
        assert_eq!(content.operations[1].operator, "cm");
    }

    #[test]
    fn content_strict_rejects_corrupted_data() {
        let data = b"q 1 0 0 1 10 10 cm (corrupted Q";
        assert!(content_strict(data).is_err());
    }

    fn on_big_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn deeply_nested_array_is_rejected() {
        on_big_stack(|| {
            let depth = 200_000;
            let mut input = Vec::with_capacity(depth * 2);
            input.extend(std::iter::repeat_n(b'[', depth));
            input.extend(std::iter::repeat_n(b']', depth));
            let result = _direct_object(crate::reader::MAX_NESTING_DEPTH)(input.as_slice());
            assert!(result.is_err());
        });
    }

    #[test]
    fn deeply_nested_dictionary_is_rejected() {
        on_big_stack(|| {
            let depth = 200_000;
            let mut input = Vec::with_capacity(depth * 6);
            for _ in 0..depth {
                input.extend_from_slice(b"<</K ");
            }
            for _ in 0..depth {
                input.extend_from_slice(b">>");
            }
            let result = _direct_object(crate::reader::MAX_NESTING_DEPTH)(input.as_slice());
            assert!(result.is_err());
        });
    }

    #[test]
    fn modestly_nested_array_still_parses() {
        let input = b"[[[[[1]]]]]";
        let obj = _direct_object(crate::reader::MAX_NESTING_DEPTH)(test_span(input));
        assert!(obj.is_ok());
    }

    #[test]
    fn content_treats_nul_and_form_feed_as_white_space() {
        // Some generators (e.g. Polaris Office) pad between operators with NUL bytes.
        let data = b"BT\n/F1 12 Tf\n[(a)] TJ\n\0\0\0\0ET\x0Cq\0Q";
        let content = content_strict(data).unwrap();
        let operators: Vec<_> = content.operations.iter().map(|op| op.operator.as_str()).collect();
        assert_eq!(operators, ["BT", "Tf", "TJ", "ET", "q", "Q"]);
    }

    #[test]
    fn content_parses_type3_glyph_operators() {
        // Type 3 glyph descriptions start with d0 or d1, whose names end in a digit.
        let data = b"750 0 d0\n0 0 m 10 10 l S\n500 0 0 -10 480 700 d1\n0 0 480 700 re f";
        let content = content_strict(data).unwrap();
        let operators: Vec<_> = content.operations.iter().map(|op| op.operator.as_str()).collect();
        assert_eq!(operators, ["d0", "m", "l", "S", "d1", "re", "f"]);
        assert_eq!(
            content.operations[0].operands,
            [Object::Integer(750), Object::Integer(0)]
        );
        assert_eq!(content.operations[4].operands.len(), 6);
    }

    #[test]
    fn content_reads_minus_sign_inside_real_as_one_operand() {
        let data = b"q\n0.99999994\n0.00-4142502\n0\n1.0000001\n106.729645\n232.27554\ncm\nQ";
        let content = content_strict(data).unwrap();
        let operators: Vec<_> = content.operations.iter().map(|op| op.operator.as_str()).collect();
        assert_eq!(operators, ["q", "cm", "Q"]);
        assert_eq!(content.operations[1].operands.len(), 6);
        assert_eq!(content.operations[1].operands[1], Object::Real(0.004142502));
    }

    #[test]
    fn space_skips_white_space_and_comments() {
        let rest = |input| space(test_span(input)).unwrap().0;
        assert_eq!(rest(b" \t\r\n\0\x0C/A"), b"/A");
        assert_eq!(rest(b"% one\n%two\r\n \0% three\r/A"), b"/A");
        assert_eq!(rest(b"/A"), b"/A");
        assert_eq!(rest(b""), b"");
        // A comment ends with an end-of-line marker, without which it is left unread.
        assert_eq!(rest(b" % unterminated"), b"% unterminated");
    }

    #[test]
    fn parse_name_ends_at_delimiters_and_invalid_escapes() {
        for (input, expected, rest) in [
            (&b"/Type/Page"[..], &b"Type"[..], &b"/Page"[..]),
            (b"/A B", b"A", b" B"),
            (b"/A(text)", b"A", b"(text)"),
            (b"/A#42C", b"ABC", b""),
            (b"/#41#4a#4A", b"AJJ", b""),
            (b"/a#20b#00", b"a b\0", b""),
            // A `#` without two hexadecimal digits ends the name.
            (b"/A#4", b"A", b"#4"),
            (b"/A#4G", b"A", b"#4G"),
            (b"/A#", b"A", b"#"),
            (b"/A# 1", b"A", b"# 1"),
            (b"/", b"", b""),
            (b"/\xe5\x90\x8d ", b"\xe5\x90\x8d", b" "),
        ] {
            assert_eq!(
                name(test_span(input)),
                Ok((rest, expected.to_vec())),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn hexadecimal_string_accepts_only_hexadecimal_digits() {
        let hex = |input| match tstrip(hexadecimal_string(test_span(input))) {
            Some(Object::String(bytes, StringFormat::Hexadecimal)) => Some(bytes),
            _ => None,
        };
        assert_eq!(hex(b"<09aFAf>"), Some(b"\x09\xaf\xaf".to_vec()));
        assert_eq!(hex(b"<>"), Some(vec![]));
        for input in [&b"<4G>"[..], b"<+1>", b"<\xc3\xa9>", b"<41"] {
            assert_eq!(hex(input), None, "{:?}", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn parse_integers_and_references_at_their_limits() {
        for (input, expected) in [
            (&b"9223372036854775807"[..], Some(Object::Integer(i64::MAX))),
            (b"-9223372036854775808", Some(Object::Integer(i64::MIN))),
            (b"+0042", Some(Object::Integer(42))),
            (b"-0", Some(Object::Integer(0))),
            // An integer outside i64 is not an object.
            (b"9223372036854775808", None),
            (b"-9223372036854775809", None),
            (b"99999999999999999999999999", None),
            (b"4294967295 65535 R", Some(Object::Reference((u32::MAX, u16::MAX)))),
            (b"0000000000000000000000001 0R", Some(Object::Reference((1, 0)))),
            (b"1 %comment\n0 R", Some(Object::Reference((1, 0)))),
            // Beyond u32 or u16, the numbers of a reference are read as integers.
            (b"4294967296 0 R", Some(Object::Integer(4_294_967_296))),
            (b"1 65536 R", Some(Object::Integer(1))),
        ] {
            assert_eq!(
                direct_object(test_span(input)),
                expected,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn parse_each_kind_of_direct_object() {
        for (input, expected) in [
            (&b"null"[..], Object::Null),
            (b"true", Object::Boolean(true)),
            (b"false", Object::Boolean(false)),
            (b"12 0 R", Object::Reference((12, 0))),
            (b"12 0", Object::Integer(12)),
            (b"1.5", Object::Real(1.5)),
            (b"-.5", Object::Real(-0.5)),
            (b"+7", Object::Integer(7)),
            (b"/N", Object::Name(b"N".to_vec())),
            (b"(s)", Object::string_literal("s")),
            (b"<73>", Object::String(b"s".to_vec(), StringFormat::Hexadecimal)),
            (b"<</N 1>>", Object::Dictionary(crate::dictionary! { "N" => 1 })),
            (
                b"[1 2.5 /N]",
                Object::Array(vec![1.into(), Object::Real(2.5), "N".into()]),
            ),
        ] {
            assert_eq!(
                direct_object(test_span(input)),
                Some(expected),
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
        for input in [&b""[..], b"nul", b"True", b"R", b")", b">>", b"]", b"{", b"-", b"."] {
            assert_eq!(
                direct_object(test_span(input)),
                None,
                "{:?}",
                String::from_utf8_lossy(input)
            );
        }
    }
}
