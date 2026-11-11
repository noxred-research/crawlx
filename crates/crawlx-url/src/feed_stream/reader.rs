//! Fixed-buffer reader that hashes exactly the bytes the parser consumed.

use crawlx_core::hash::Digest;
use std::io::{self, BufRead, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Domain tag of the consumed-prefix digest stored in a stream cursor.
pub(super) const PREFIX_DOMAIN: &str = "crawlx.feed-stream.prefix.v1";

/// Digest of an empty prefix.
pub(super) fn empty_digest() -> Digest {
    Digest::of(PREFIX_DOMAIN, &[])
}

/// Digest of `bytes` as a consumed prefix; equals [`HashedReader::digest`] after consuming `bytes`.
pub(super) fn prefix_digest(bytes: &[u8]) -> Digest {
    Digest::of(PREFIX_DOMAIN, bytes)
}

/// `BufRead` over `R` with one fixed chunk buffer, a running prefix hash and an optional
/// per-read byte budget so a parser cannot grow its own buffer without bound.
pub(super) struct HashedReader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
    hasher: blake3::Hasher,
    consumed: u64,
    budget: usize,
    over_budget: Arc<AtomicBool>,
}

impl<R: Read> HashedReader<R> {
    pub(super) fn new(inner: R, chunk: usize) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PREFIX_DOMAIN.as_bytes());
        hasher.update(&[0]);
        Self {
            inner,
            buf: vec![0; chunk.max(64)],
            pos: 0,
            cap: 0,
            hasher,
            consumed: 0,
            budget: usize::MAX,
            over_budget: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Allow at most `bytes` consumed bytes before the budget flag trips and refills fail.
    pub(super) fn reset_budget(&mut self, bytes: usize) {
        self.budget = bytes;
    }

    /// Flag set once more bytes were consumed under one budget than it allowed.
    pub(super) fn over_budget_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.over_budget)
    }

    /// Bytes handed to the parser so far.
    pub(super) fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Size of the fixed chunk buffer.
    pub(super) fn chunk_len(&self) -> usize {
        self.buf.len()
    }

    /// Digest of every consumed byte.
    pub(super) fn digest(&self) -> Digest {
        Digest(*self.hasher.clone().finalize().as_bytes())
    }
}

impl<R: Read> Read for HashedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = {
            let available = self.fill_buf()?;
            let n = available.len().min(out.len());
            out[..n].copy_from_slice(&available[..n]);
            n
        };
        self.consume(n);
        Ok(n)
    }
}

impl<R: Read> BufRead for HashedReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.cap {
            if self.budget == 0 {
                self.over_budget.store(true, Ordering::Relaxed);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "event byte budget exhausted",
                ));
            }
            loop {
                match self.inner.read(&mut self.buf) {
                    Ok(n) => {
                        self.pos = 0;
                        self.cap = n;
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(&self.buf[self.pos..self.cap])
    }

    fn consume(&mut self, amount: usize) {
        let amount = amount.min(self.cap - self.pos);
        self.hasher.update(&self.buf[self.pos..self.pos + amount]);
        self.pos += amount;
        self.consumed = self
            .consumed
            .saturating_add(u64::try_from(amount).unwrap_or(u64::MAX));
        if amount > self.budget {
            self.over_budget.store(true, Ordering::Relaxed);
        }
        self.budget = self.budget.saturating_sub(amount);
    }
}
