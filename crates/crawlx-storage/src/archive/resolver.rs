//! One bounded, zero-network record graph and logical payload resolver for all offline consumers.

use super::{warc, ArchiveError, Limits};
use std::collections::{BTreeMap, BTreeSet};

/// Location of one validated physical WARC member within an approved local source.
#[derive(Clone, Debug)]
pub struct RecordLocation {
    /// Index of the already-open approved source, never a URL or filesystem path from WARC headers.
    pub source: usize,
    /// Validated ZIP member name, empty for a standalone WARC.
    pub filename: String,
    /// Physical member facts; a logical origin may describe a segmented representation.
    pub record: warc::RecordSummary,
}

/// Materialized bounded payload with both requested-event and actual payload-source provenance.
#[derive(Clone, Debug)]
pub struct ResolvedPayload {
    /// Actual stored entity bytes after WARC segmentation and HTTP transfer framing removal.
    pub bytes: Vec<u8>,
    /// Requested event, including its real revisit status/date and physical member range.
    pub requested: warc::RecordSummary,
    /// Actual non-revisit representation that supplied the payload, with logical MIME/status/digest.
    pub source: warc::RecordSummary,
}

pub(crate) struct Catalog {
    entries: BTreeMap<String, RecordLocation>,
    continuations: BTreeMap<String, Vec<String>>,
    limits: Limits,
}

impl Catalog {
    pub(crate) fn new(
        entries: impl IntoIterator<Item = RecordLocation>,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        let mut by_id = BTreeMap::new();
        let mut continuations: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut expanded = 0u64;
        for entry in entries {
            if by_id.len() as u64 >= u64::from(limits.records) {
                return Err(ArchiveError::Limit("collection record count"));
            }
            expanded = expanded
                .checked_add(entry.record.uncompressed_length)
                .ok_or(ArchiveError::Limit("collection expanded bytes"))?;
            if expanded > limits.expanded_bytes {
                return Err(ArchiveError::Limit("collection expanded bytes"));
            }
            if entry.record.record_type == "continuation" {
                let origin = entry
                    .record
                    .dependencies
                    .first()
                    .ok_or(ArchiveError::Invalid("segment origin missing"))?;
                continuations
                    .entry(origin.clone())
                    .or_default()
                    .push(entry.record.id.clone());
            }
            if by_id.insert(entry.record.id.clone(), entry).is_some() {
                return Err(ArchiveError::Invalid("duplicate collection record identifier"));
            }
        }
        resolve_target_dates(&mut by_id)?;
        for ids in continuations.values_mut() {
            ids.sort_by_key(|id| by_id.get(id).and_then(|entry| entry.record.segment_number));
        }
        let catalog = Self {
            entries: by_id,
            continuations,
            limits,
        };
        catalog.validate_graph()?;
        for entry in catalog.entries.values() {
            if entry.record.segment_number == Some(1) {
                catalog.segments(&entry.record.id)?;
            }
            if entry.record.record_type == "continuation" {
                let origin = entry
                    .record
                    .dependencies
                    .first()
                    .ok_or(ArchiveError::Invalid("segment origin missing"))?;
                if catalog.entry(origin)?.record.segment_number != Some(1) {
                    return Err(ArchiveError::Invalid(
                        "continuation does not reference a logical origin",
                    ));
                }
            }
        }
        Ok(catalog)
    }

    fn entry(&self, id: &str) -> Result<&RecordLocation, ArchiveError> {
        self.entries.get(id).ok_or(ArchiveError::CapabilityUnavailable(
            "local_record_dependency_unavailable_no_network_fallback",
        ))
    }

    fn validate_graph(&self) -> Result<(), ArchiveError> {
        let mut complete: BTreeMap<&str, u32> = BTreeMap::new();
        for id in self.entries.keys() {
            let mut active = BTreeSet::new();
            let mut stack = vec![(id.as_str(), false, 0u32)];
            while let Some((id, leaving, depth)) = stack.pop() {
                if depth > self.limits.dependency_depth {
                    return Err(ArchiveError::Limit("dependency depth"));
                }
                if leaving {
                    active.remove(id);
                    let height = self
                        .entry(id)?
                        .record
                        .dependencies
                        .iter()
                        .map(|dependency| {
                            complete
                                .get(dependency.as_str())
                                .copied()
                                .unwrap_or(0)
                                .saturating_add(1)
                        })
                        .max()
                        .unwrap_or(0);
                    if height > self.limits.dependency_depth {
                        return Err(ArchiveError::Limit("dependency depth"));
                    }
                    complete.insert(id, height);
                    continue;
                }
                if active.contains(id) {
                    return Err(ArchiveError::Invalid("cyclic record dependency"));
                }
                if let Some(height) = complete.get(id) {
                    if depth
                        .checked_add(*height)
                        .is_none_or(|total| total > self.limits.dependency_depth)
                    {
                        return Err(ArchiveError::Limit("dependency depth"));
                    }
                    continue;
                }
                let entry = self.entry(id)?;
                if entry.record.record_type == "revisit"
                    && !matches!(
                        entry.record.revisit_profile.as_deref(),
                        Some(
                            "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest"
                                | "http://netpreserve.org/warc/1.1/revisit/server-not-modified"
                        )
                    )
                {
                    return Err(ArchiveError::CapabilityUnavailable(
                        "unsupported_revisit_profile_not_executed",
                    ));
                }
                active.insert(id);
                stack.push((id, true, depth));
                for dependency in entry.record.dependencies.iter().rev() {
                    let target = self.entry(dependency)?;
                    if entry.record.record_type == "revisit" {
                        if !matches!(
                            target.record.record_type.as_str(),
                            "response" | "resource" | "conversion" | "revisit"
                        ) {
                            return Err(ArchiveError::Invalid(
                                "revisit baseline has no representation payload",
                            ));
                        }
                        if entry
                            .record
                            .refers_to_target
                            .as_ref()
                            .is_some_and(|url| target.record.target.as_ref() != Some(url))
                            || entry
                                .record
                                .refers_to_date
                                .is_some_and(|date| target.record.date != date)
                        {
                            return Err(ArchiveError::Invalid("revisit target or date mismatch"));
                        }
                    }
                    stack.push((dependency.as_str(), false, depth + 1));
                }
            }
        }
        Ok(())
    }

    fn origin(&self, id: &str) -> Result<&RecordLocation, ArchiveError> {
        let mut entry = self.entry(id)?;
        for _ in 0..=self.limits.dependency_depth {
            if matches!(entry.record.record_type.as_str(), "revisit" | "continuation") {
                let id = entry
                    .record
                    .dependencies
                    .first()
                    .ok_or(ArchiveError::Invalid("payload source unavailable"))?;
                entry = self.entry(id)?;
            } else {
                return Ok(entry);
            }
        }
        Err(ArchiveError::Limit("payload dependency depth"))
    }

    fn segments(&self, origin: &str) -> Result<Vec<&RecordLocation>, ArchiveError> {
        let first = self.entry(origin)?;
        let mut segments = vec![first];
        if first.record.segment_number != Some(1) {
            return Ok(segments);
        }
        let ids = self
            .continuations
            .get(origin)
            .ok_or(ArchiveError::Invalid("unfinished segmented record"))?;
        let mut number = 2u32;
        let mut total = first.record.block_length;
        if first.record.segment_total_length.is_some() {
            return Err(ArchiveError::Invalid("segment total length on first segment"));
        }
        for (index, id) in ids.iter().enumerate() {
            let entry = self.entry(id)?;
            if entry.record.segment_number != Some(number) || entry.record.target != first.record.target {
                return Err(ArchiveError::Invalid("segment ordering or target mismatch"));
            }
            if !entry.record.payload_digest.is_empty()
                && !first.record.payload_digest.is_empty()
                && !warc::same_digest(&entry.record.payload_digest, &first.record.payload_digest)
            {
                return Err(ArchiveError::Invalid("segment logical digest mismatch"));
            }
            total = total
                .checked_add(entry.record.block_length)
                .ok_or(ArchiveError::Limit("logical record bytes"))?;
            if total > self.limits.record_bytes {
                return Err(ArchiveError::Limit("logical record bytes"));
            }
            let last = index + 1 == ids.len();
            if last {
                if entry.record.segment_total_length != Some(total) {
                    return Err(ArchiveError::Invalid("segment final length mismatch"));
                }
            } else if entry.record.segment_total_length.is_some() {
                return Err(ArchiveError::Invalid("premature final segment"));
            }
            segments.push(entry);
            number = number
                .checked_add(1)
                .ok_or(ArchiveError::Limit("segment count"))?;
        }
        Ok(segments)
    }

    pub(crate) fn materialize(
        &self,
        id: &str,
        read: &mut impl FnMut(&RecordLocation) -> Result<Vec<u8>, ArchiveError>,
    ) -> Result<ResolvedPayload, ArchiveError> {
        let requested = self.entry(id)?;
        let origin = self.origin(id)?;
        if matches!(origin.record.record_type.as_str(), "warcinfo" | "metadata") {
            return Err(ArchiveError::CapabilityUnavailable(
                "record_has_no_defined_payload",
            ));
        }
        let segments = self.segments(&origin.record.id)?;
        let (mut block, headers_safe) = self.assemble(&segments, read)?;
        let mut source = origin.record.clone();
        let (offset, status, mime, chunked) =
            warc::logical_http(&source.record_type, &block, self.limits, source.truncated)?;
        source.payload_offset = offset as u64;
        source.status = status.or(source.status);
        if let Some(mime) = mime {
            source.mime = mime;
        }
        source.transfer_chunked = chunked;
        source.retention_approved = headers_safe && warc::retention_safe_text(&block, &source.mime);
        let bytes = if chunked {
            warc::decode_chunks(&block[offset..], self.limits.record_bytes)?
        } else {
            if offset > 0 {
                drop(block.drain(..offset));
            }
            block
        };
        if chunked {
            source.retention_approved &= warc::retention_safe_text(&bytes, &source.mime);
        }
        let computed = warc::digest(&bytes);
        for entry in &segments {
            if !entry.record.payload_digest.is_empty()
                && !warc::same_digest(&entry.record.payload_digest, &computed)
            {
                return Err(ArchiveError::Invalid("logical payload digest mismatch"));
            }
        }
        if !requested.record.payload_digest.is_empty()
            && !warc::same_digest(&requested.record.payload_digest, &computed)
        {
            return Err(ArchiveError::Invalid("revisit baseline digest mismatch"));
        }
        source.payload_digest = computed;
        let mut requested_record = requested.record.clone();
        requested_record.retention_approved = self.chain_approved(id)? && source.retention_approved;
        Ok(ResolvedPayload {
            bytes,
            requested: requested_record,
            source,
        })
    }

    fn assemble(
        &self,
        segments: &[&RecordLocation],
        read: &mut impl FnMut(&RecordLocation) -> Result<Vec<u8>, ArchiveError>,
    ) -> Result<(Vec<u8>, bool), ArchiveError> {
        let first = segments
            .first()
            .ok_or(ArchiveError::Invalid("logical record has no origin"))?;
        let total = segments.iter().try_fold(0u64, |total, entry| {
            total
                .checked_add(entry.record.block_length)
                .ok_or(ArchiveError::Limit("logical record bytes"))
        })?;
        if total > self.limits.record_bytes {
            return Err(ArchiveError::Limit("logical record bytes"));
        }
        let mut block = read(first)?;
        if block.len() as u64 != first.record.block_length {
            return Err(ArchiveError::Invalid("logical member length changed"));
        }
        let capacity = usize::try_from(total).map_err(|_| ArchiveError::Limit("logical record bytes"))?;
        block.reserve_exact(capacity.saturating_sub(block.len()));
        let mut approved = first.record.headers_retention_approved;
        for entry in segments.iter().skip(1) {
            let bytes = read(entry)?;
            if bytes.len() as u64 != entry.record.block_length {
                return Err(ArchiveError::Invalid("logical member length changed"));
            }
            approved &= entry.record.headers_retention_approved;
            block.extend_from_slice(&bytes);
        }
        Ok((block, approved))
    }

    fn chain_approved(&self, id: &str) -> Result<bool, ArchiveError> {
        let mut entry = self.entry(id)?;
        let mut approved = true;
        for _ in 0..=self.limits.dependency_depth {
            approved &= entry.record.retention_approved;
            if !matches!(entry.record.record_type.as_str(), "revisit" | "continuation") {
                return Ok(approved);
            }
            entry = self.entry(
                entry
                    .record
                    .dependencies
                    .first()
                    .ok_or(ArchiveError::Invalid("payload source unavailable"))?,
            )?;
        }
        Err(ArchiveError::Limit("payload dependency depth"))
    }

    pub(crate) fn validate(
        &mut self,
        read: &mut impl FnMut(&RecordLocation) -> Result<Vec<u8>, ArchiveError>,
    ) -> Result<(), ArchiveError> {
        let origins = self
            .entries
            .values()
            .filter(|entry| entry.record.segment_number == Some(1))
            .map(|entry| entry.record.id.clone())
            .collect::<Vec<_>>();
        for id in origins {
            let record = self.entry(&id)?.record.clone();
            let normalized = if matches!(record.record_type.as_str(), "revisit" | "metadata" | "warcinfo") {
                let segments = self.segments(&id)?;
                let (block, headers_safe) = self.assemble(&segments, read)?;
                let mut normalized = record;
                if normalized.record_type == "revisit" {
                    let (offset, status, mime, chunked) =
                        warc::logical_http("revisit", &block, self.limits, normalized.truncated)?;
                    if offset != block.len() {
                        return Err(ArchiveError::Invalid(
                            "revisit profile contains an unexpected stored payload",
                        ));
                    }
                    normalized.payload_offset = offset as u64;
                    normalized.status = status;
                    normalized.transfer_chunked = chunked;
                    if let Some(mime) = mime {
                        normalized.mime = mime;
                    }
                } else if segments
                    .iter()
                    .any(|segment| !segment.record.payload_digest.is_empty())
                {
                    return Err(ArchiveError::Invalid(
                        "logical metadata record has no defined payload",
                    ));
                }
                normalized.retention_approved =
                    headers_safe && warc::retention_safe_text(&block, &normalized.mime);
                normalized
            } else {
                self.materialize(&id, read)?.source
            };
            let mut ids = vec![id.clone()];
            if let Some(tails) = self.continuations.get(&id) {
                ids.extend(tails.iter().cloned());
            }
            for segment in ids {
                let entry = self
                    .entries
                    .get_mut(&segment)
                    .ok_or(ArchiveError::Invalid("segment disappeared"))?;
                entry.record.retention_approved = normalized.retention_approved;
                entry.record.payload_digest = normalized.payload_digest.clone();
                if segment == id {
                    entry.record.mime = normalized.mime.clone();
                    entry.record.status = normalized.status;
                    entry.record.payload_offset = normalized.payload_offset;
                    entry.record.transfer_chunked = normalized.transfer_chunked;
                }
            }
        }
        let mut digests = Vec::new();
        for entry in self.entries.values() {
            if entry.record.record_type == "revisit" {
                let baseline = self.origin(&entry.record.id)?;
                if !entry.record.payload_digest.is_empty()
                    && !warc::same_digest(&entry.record.payload_digest, &baseline.record.payload_digest)
                {
                    return Err(ArchiveError::Invalid("revisit baseline digest mismatch"));
                }
                if entry.record.revisit_profile.as_deref()
                    == Some("http://netpreserve.org/warc/1.1/revisit/server-not-modified")
                    && (entry.record.target != baseline.record.target
                        || entry.record.date < baseline.record.date)
                {
                    return Err(ArchiveError::Invalid(
                        "conditional revisit baseline representation mismatch",
                    ));
                }
                digests.push((entry.record.id.clone(), baseline.record.payload_digest.clone()));
            }
        }
        for (id, digest) in digests {
            self.entries
                .get_mut(&id)
                .ok_or(ArchiveError::Invalid("revisit disappeared"))?
                .record
                .payload_digest = digest;
        }
        let approvals = self
            .entries
            .values()
            .filter(|entry| entry.record.record_type == "revisit")
            .map(|entry| {
                self.chain_approved(&entry.record.id)
                    .map(|approved| (entry.record.id.clone(), approved))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (id, approved) in approvals {
            self.entries
                .get_mut(&id)
                .ok_or(ArchiveError::Invalid("revisit disappeared"))?
                .record
                .retention_approved = approved;
        }
        Ok(())
    }

    pub(crate) fn locations(&self) -> impl Iterator<Item = &RecordLocation> {
        self.entries.values()
    }
    pub(crate) fn location(&self, id: &str) -> Result<&RecordLocation, ArchiveError> {
        self.entry(id)
    }
}

fn resolve_target_dates(entries: &mut BTreeMap<String, RecordLocation>) -> Result<(), ArchiveError> {
    let unresolved = entries
        .values()
        .filter(|entry| entry.record.record_type == "revisit" && entry.record.dependencies.is_empty())
        .map(|entry| entry.record.id.as_str())
        .collect::<Vec<_>>();
    if unresolved.is_empty() {
        return Ok(());
    }
    let mut by_target: BTreeMap<(&str, chrono::DateTime<chrono::Utc>), Vec<&str>> = BTreeMap::new();
    for entry in entries.values() {
        if !matches!(
            entry.record.record_type.as_str(),
            "response" | "resource" | "conversion" | "revisit"
        ) || entry.record.segment_number.is_some_and(|number| number != 1)
        {
            continue;
        }
        if let Some(target) = entry.record.target.as_deref() {
            by_target
                .entry((target, entry.record.date))
                .or_default()
                .push(&entry.record.id);
        }
    }
    let mut resolved = Vec::new();
    for id in unresolved {
        let record = &entries
            .get(id)
            .ok_or(ArchiveError::Invalid("revisit disappeared"))?
            .record;
        let target = record
            .refers_to_target
            .as_deref()
            .ok_or(ArchiveError::Invalid("revisit target missing"))?;
        let date = record
            .refers_to_date
            .ok_or(ArchiveError::Invalid("revisit date missing"))?;
        let candidates = by_target
            .get(&(target, date))
            .ok_or(ArchiveError::CapabilityUnavailable(
                "local_revisit_target_date_unavailable_no_network_fallback",
            ))?;
        let mut matches = candidates.iter().copied().filter(|candidate| *candidate != id);
        let baseline = matches.next().ok_or(ArchiveError::CapabilityUnavailable(
            "local_revisit_target_date_unavailable_no_network_fallback",
        ))?;
        if matches.next().is_some() {
            return Err(ArchiveError::Invalid(
                "ambiguous revisit target and date require an explicit record identifier",
            ));
        }
        resolved.push((id.to_owned(), baseline.to_owned()));
    }
    drop(by_target);
    for (id, baseline) in resolved {
        entries
            .get_mut(&id)
            .ok_or(ArchiveError::Invalid("revisit disappeared"))?
            .record
            .dependencies
            .push(baseline);
    }
    Ok(())
}
