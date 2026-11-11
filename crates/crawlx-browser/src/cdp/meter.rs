//! Frame-aligned byte admission for the DevTools socket.
//!
//! The WebSocket codec allocates a frame's whole payload buffer as soon as it has parsed the
//! frame header, before one payload byte has arrived. [`FrameMeter`] sits between the TCP
//! stream and the codec and withholds every header until the shared byte budget admits the
//! frame it announces, so the reservation always precedes the allocation. It never reads past
//! the end of a frame, which keeps the codec's buffers exactly aligned with what was charged.
//!
//! While admission is refused the meter stops reading the socket (TCP back-pressure on the
//! browser) for a bounded time, then fails the connection with a typed refusal that
//! [`Admission::refusal`] reports. Frames and assembled messages above the configured limit are
//! refused from their header alone.
//!
//! The HTTP upgrade response is read one byte at a time (at most `MAX_UPGRADE` bytes) and the
//! meter arms itself at its terminating blank line, so a frame that arrives in the same segment
//! as the response is never read ahead into the codec: it passes through the metered path like
//! every later frame. The upgrade bytes themselves sit in the connection's fixed baseline.

use crawlx_core::parser_memory::{ByteAdmissionError, ByteBudget, BytePermit};
use parking_lot::Mutex;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{sleep, Instant, Sleep};

/// Bytes charged per payload byte of an inbound frame: the codec's frame buffer plus the
/// reassembly copy a fragmented message needs. The charge then moves with the decoded text.
pub(super) const WIRE_WEIGHT: usize = 2;
/// Longest WebSocket frame header a server sends: 2 bytes, 8 length bytes, 4 mask bytes.
const MAX_HEADER: usize = 14;
/// Pause between two admission attempts while the budget is exhausted.
const RETRY_INTERVAL: Duration = Duration::from_millis(10);

/// Budget handle shared between the stream wrapper and the connection driver.
#[derive(Debug)]
pub(super) struct Admission {
    budget: Arc<ByteBudget>,
    held: Mutex<Option<BytePermit>>,
    armed: AtomicBool,
    refusal: Mutex<Option<ByteAdmissionError>>,
    max_message: usize,
    wait: Duration,
}

impl Admission {
    pub(super) fn new(budget: &Arc<ByteBudget>, max_message: usize, wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            budget: Arc::clone(budget),
            held: Mutex::new(None),
            armed: AtomicBool::new(false),
            refusal: Mutex::new(None),
            max_message,
            wait,
        })
    }

    /// Start metering; called once the WebSocket upgrade completed.
    pub(super) fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    /// The admission refusal that failed the stream, if that is why it failed.
    pub(super) fn refusal(&self) -> Option<ByteAdmissionError> {
        *self.refusal.lock()
    }

    /// Move every byte admitted for the frames read since the previous call to the caller.
    /// Call after the codec yielded one complete data message; the permit then travels with
    /// that message's bytes.
    ///
    /// # Errors
    /// Only the arithmetic of an empty reservation can refuse.
    pub(super) fn take_message(&self) -> Result<BytePermit, ByteAdmissionError> {
        match self.held.lock().take() {
            Some(permit) => Ok(permit),
            None => self.budget.try_reserve(0),
        }
    }

    fn grow(&self, bytes: usize) -> Result<(), ByteAdmissionError> {
        let mut held = self.held.lock();
        match held.as_mut() {
            Some(permit) => permit.grow_by(bytes),
            None => {
                *held = Some(self.budget.try_reserve(bytes)?);
                Ok(())
            }
        }
    }
}

/// `AsyncRead + AsyncWrite` wrapper that admits every inbound frame against the budget.
#[derive(Debug)]
pub(super) struct FrameMeter<S> {
    inner: S,
    admission: Arc<Admission>,
    head: [u8; MAX_HEADER],
    head_have: usize,
    /// Header length once the first two bytes are known, else `0`.
    head_len: usize,
    head_out: usize,
    /// Payload bytes of the current frame not yet delivered.
    payload: usize,
    admitted: bool,
    /// Data bytes of the message still being assembled.
    message: usize,
    /// Upgrade-response bytes read so far.
    upgrade_len: usize,
    /// Progress through the `\r\n\r\n` that ends the upgrade response.
    blank: u8,
    /// Bytes read past the upgrade response, awaiting the metered frame path.
    pre: Vec<u8>,
    /// Leading bytes of `pre` that are upgrade response, not yet delivered.
    up_ready: usize,
    retry: Option<Pin<Box<Sleep>>>,
    give_up: Option<Instant>,
}

/// Longest HTTP upgrade response accepted, in bytes.
const MAX_UPGRADE: usize = 16 * 1024;
/// Socket read size during the upgrade, and so the most the prebuffer ever holds.
const UPGRADE_CHUNK: usize = 4096;

impl<S> FrameMeter<S> {
    pub(super) fn new(inner: S, admission: Arc<Admission>) -> Self {
        Self {
            inner,
            admission,
            head: [0; MAX_HEADER],
            head_have: 0,
            head_len: 0,
            head_out: 0,
            payload: 0,
            admitted: false,
            message: 0,
            upgrade_len: 0,
            blank: 0,
            pre: Vec::new(),
            up_ready: 0,
            retry: None,
            give_up: None,
        }
    }

    /// Next bytes of the stream: the owned prebuffer first (what followed the upgrade
    /// response in its segment), then the socket.
    fn poll_src(&mut self, cx: &mut Context<'_>, window: &mut ReadBuf<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        if self.pre.is_empty() {
            return Pin::new(&mut self.inner).poll_read(cx, window);
        }
        let n = window.remaining().min(self.pre.len());
        window.put_slice(&self.pre[..n]);
        self.pre.drain(..n);
        Poll::Ready(Ok(()))
    }

    /// Deliver the HTTP upgrade response to the codec, and only the response. The socket is
    /// read in chunks (the codec's flood check rejects a handshake read in tiny pieces); bytes
    /// that follow the terminating blank line stay in the owned `pre` buffer, at most one
    /// chunk, inside the connection's fixed baseline, and reach the codec afterwards through
    /// the metered frame path, never unadmitted. The response is capped at [`MAX_UPGRADE`].
    fn poll_upgrade(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        if self.up_ready == 0 {
            let mut chunk = [0u8; UPGRADE_CHUNK];
            let mut window = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut window))?;
            let got = window.filled();
            if got.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let mut response = got.len();
            for (index, &byte) in got.iter().enumerate() {
                self.blank = match (self.blank, byte) {
                    (0 | 2, b'\r') => self.blank + 1,
                    (1 | 3, b'\n') => self.blank + 1,
                    (_, b'\r') => 1,
                    _ => 0,
                };
                if self.blank == 4 {
                    response = index + 1;
                    self.admission.arm();
                    break;
                }
            }
            self.upgrade_len += response;
            if self.upgrade_len > MAX_UPGRADE {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "websocket upgrade response exceeds its limit",
                )));
            }
            self.pre.extend_from_slice(got);
            self.up_ready = response;
        }
        let n = buf.remaining().min(self.up_ready);
        buf.put_slice(&self.pre[..n]);
        self.pre.drain(..n);
        self.up_ready -= n;
        Poll::Ready(Ok(()))
    }

    fn reset_frame(&mut self) {
        self.head_have = 0;
        self.head_len = 0;
        self.head_out = 0;
        self.payload = 0;
        self.admitted = false;
    }

    /// Parse the complete header: the frame's payload size and the message-size limits.
    fn begin_frame(&mut self) -> io::Result<()> {
        let invalid = |what: &'static str| io::Error::new(io::ErrorKind::InvalidData, what);
        let first = self.head[0];
        let fin = first & 0x80 != 0;
        let control = first & 0x08 != 0;
        let payload = match self.head[1] & 0x7f {
            126 => usize::from(u16::from_be_bytes([self.head[2], self.head[3]])),
            127 => {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.head[2..10]);
                usize::try_from(u64::from_be_bytes(raw))
                    .map_err(|_| invalid("websocket frame length overflows"))?
            }
            short => usize::from(short),
        };
        if control {
            if payload > 125 {
                return Err(invalid("websocket control frame too long"));
            }
        } else {
            let total = self
                .message
                .checked_add(payload)
                .filter(|total| *total <= self.admission.max_message)
                .ok_or_else(|| invalid("websocket message exceeds the configured limit"))?;
            self.message = if fin { 0 } else { total };
        }
        self.payload = payload;
        Ok(())
    }

    /// Reserve the frame's bytes, waiting a bounded time while the budget is exhausted.
    fn poll_admit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(bytes) = self.payload.checked_mul(WIRE_WEIGHT) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket frame length overflows",
            )));
        };
        loop {
            let refused = match self.admission.grow(bytes) {
                Ok(()) => {
                    self.retry = None;
                    self.give_up = None;
                    self.admitted = true;
                    return Poll::Ready(Ok(()));
                }
                Err(refused) => refused,
            };
            let now = Instant::now();
            let deadline = *self.give_up.get_or_insert(now + self.admission.wait);
            if refused.exceeds_budget() || now >= deadline {
                *self.admission.refusal.lock() = Some(refused);
                return Poll::Ready(Err(io::Error::other(refused)));
            }
            let timer = self.retry.get_or_insert_with(|| Box::pin(sleep(RETRY_INTERVAL)));
            ready!(timer.as_mut().poll(cx));
            self.retry = None;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FrameMeter<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        if this.up_ready > 0 || !this.admission.armed.load(Ordering::Acquire) {
            return this.poll_upgrade(cx, buf);
        }
        loop {
            if this.head_len != 0 && this.admitted {
                if this.head_out < this.head_len {
                    let n = buf.remaining().min(this.head_len - this.head_out);
                    buf.put_slice(&this.head[this.head_out..this.head_out + n]);
                    this.head_out += n;
                    return Poll::Ready(Ok(()));
                }
                if this.payload == 0 {
                    this.reset_frame();
                    continue;
                }
                let take = this.payload.min(buf.remaining());
                let n = {
                    let mut window = ReadBuf::new(&mut buf.initialize_unfilled()[..take]);
                    ready!(this.poll_src(cx, &mut window))?;
                    window.filled().len()
                };
                buf.advance(n);
                this.payload -= n;
                if this.payload == 0 && n != 0 {
                    // Header bytes are all delivered; the next read starts the next frame.
                    this.reset_frame();
                }
                return Poll::Ready(Ok(()));
            }
            if this.head_len != 0 {
                ready!(this.poll_admit(cx))?;
                continue;
            }
            let have = this.head_have;
            // two bytes first, then exactly the extended-length and mask bytes they announce
            let end = if have < 2 { 2 } else { header_len(this.head[1]) };
            let mut scratch = [0u8; MAX_HEADER];
            let n = {
                let mut window = ReadBuf::new(&mut scratch[..end - have]);
                ready!(this.poll_src(cx, &mut window))?;
                window.filled().len()
            };
            this.head[have..have + n].copy_from_slice(&scratch[..n]);
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            this.head_have += n;
            if this.head_have >= 2 && this.head_have == header_len(this.head[1]) {
                this.head_len = this.head_have;
                this.begin_frame()?;
            }
        }
    }
}

/// Header length announced by the second header byte (mask bit and 7-bit length).
const fn header_len(second: u8) -> usize {
    let extended = match second & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask = if second & 0x80 != 0 { 4 } else { 0 };
    2 + extended + mask
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FrameMeter<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Rig = (
        Arc<ByteBudget>,
        Arc<Admission>,
        FrameMeter<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    );

    fn metered(limit: usize, wait: Duration) -> Rig {
        let budget = Arc::new(ByteBudget::new(limit));
        let admission = Admission::new(&budget, usize::MAX, wait);
        admission.arm();
        let (near, far) = tokio::io::duplex(1 << 16);
        (
            budget,
            Arc::clone(&admission),
            FrameMeter::new(near, admission),
            far,
        )
    }

    #[tokio::test]
    async fn frame_is_charged_from_its_header_and_moves_with_the_message() {
        let (budget, admission, mut meter, mut far) = metered(1 << 20, Duration::from_millis(50));
        far.write_all(&[0x81, 5]).await.unwrap();
        let mut head = [0u8; 2];
        meter.read_exact(&mut head).await.unwrap();
        assert_eq!(head, [0x81, 5]);
        // the payload has not arrived, yet its bytes are already admitted
        assert_eq!(budget.used(), 5 * WIRE_WEIGHT);
        far.write_all(b"hello").await.unwrap();
        let mut body = [0u8; 5];
        meter.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"hello");
        let permit = admission.take_message().unwrap();
        assert_eq!(permit.bytes(), 5 * WIRE_WEIGHT);
        drop(permit);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn oversized_header_is_refused_before_any_payload_is_read() {
        let (budget, admission, mut meter, mut far) = metered(1024, Duration::from_millis(50));
        far.write_all(&[0x81, 127]).await.unwrap();
        far.write_all(&(1u64 << 20).to_be_bytes()).await.unwrap();
        let mut sink = [0u8; 64];
        assert!(meter.read(&mut sink).await.is_err());
        let refused = admission.refusal().unwrap();
        assert!(refused.exceeds_budget());
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn message_limit_applies_across_fragments() {
        let budget = Arc::new(ByteBudget::new(1 << 20));
        let admission = Admission::new(&budget, 8, Duration::from_millis(50));
        admission.arm();
        let (near, mut far) = tokio::io::duplex(1 << 10);
        let mut meter = FrameMeter::new(near, Arc::clone(&admission));
        // two fragments of 5 bytes: each below the limit, together above it
        far.write_all(&[0x01, 5]).await.unwrap();
        far.write_all(&[b'a'; 5]).await.unwrap();
        far.write_all(&[0x80, 5]).await.unwrap();
        let mut chunk = [0u8; 7];
        meter.read_exact(&mut chunk).await.unwrap();
        let mut next = [0u8; 2];
        assert!(meter.read_exact(&mut next).await.is_err());
        assert!(
            admission.refusal().is_none(),
            "a message limit is not an admission refusal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pressure_waits_for_release_then_admits() {
        let (budget, _admission, mut meter, mut far) = metered(100, Duration::from_secs(5));
        let other = budget.try_reserve(90).unwrap();
        far.write_all(&[0x81, 40]).await.unwrap();
        let release = tokio::spawn(async move {
            sleep(Duration::from_millis(30)).await;
            drop(other);
        });
        let mut head = [0u8; 2];
        meter.read_exact(&mut head).await.unwrap();
        release.await.unwrap();
        assert_eq!(budget.used(), 80);
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_pressure_fails_with_a_typed_refusal() {
        let (budget, admission, mut meter, mut far) = metered(100, Duration::from_millis(50));
        let _other = budget.try_reserve(90).unwrap();
        far.write_all(&[0x81, 40]).await.unwrap();
        let mut head = [0u8; 2];
        assert!(meter.read_exact(&mut head).await.is_err());
        let refused = admission.refusal().unwrap();
        assert!(!refused.exceeds_budget());
        assert_eq!(budget.used(), 90);
    }

    #[tokio::test]
    async fn concurrent_connections_share_one_budget() {
        let budget = Arc::new(ByteBudget::new(200));
        let mut streams = Vec::new();
        for _ in 0..2 {
            let admission = Admission::new(&budget, usize::MAX, Duration::ZERO);
            admission.arm();
            let (near, mut far) = tokio::io::duplex(256);
            far.write_all(&[0x81, 60]).await.unwrap();
            streams.push((FrameMeter::new(near, Arc::clone(&admission)), admission, far));
        }
        let mut head = [0u8; 2];
        let (first, rest) = streams.split_first_mut().unwrap();
        first.0.read_exact(&mut head).await.unwrap();
        assert_eq!(budget.used(), 120);
        // 120 + 120 exceeds 200: the second connection is refused while the first is held
        assert!(rest[0].0.read_exact(&mut head).await.is_err());
        assert!(rest[0].1.refusal().is_some());
        assert_eq!(budget.used(), 120);
    }
}

#[cfg(test)]
mod upgrade_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn frame_coalesced_with_the_upgrade_response_is_still_admitted() {
        let budget = Arc::new(ByteBudget::new(1 << 20));
        let admission = Admission::new(&budget, usize::MAX, Duration::from_millis(50));
        let (near, mut far) = tokio::io::duplex(1 << 12);
        let mut meter = FrameMeter::new(near, Arc::clone(&admission));
        // one segment: the response, then a complete text frame
        far.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello")
            .await
            .unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            let mut window = [0u8; 64];
            let n = meter.read(&mut window).await.unwrap();
            assert!(n > 0);
            response.extend_from_slice(&window[..n]);
        }
        assert!(response.starts_with(b"HTTP/1.1 101"));
        assert!(
            !response.contains(&0x81),
            "the codec got the response and nothing after it"
        );
        assert_eq!(budget.used(), 0, "nothing past the blank line was read ahead");
        let mut frame = [0u8; 2];
        meter.read_exact(&mut frame).await.unwrap();
        assert_eq!(
            budget.used(),
            5 * WIRE_WEIGHT,
            "the coalesced frame was admitted, not bypassed"
        );
        let mut body = [0u8; 5];
        meter.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"hello");
    }

    #[tokio::test]
    async fn unterminated_upgrade_response_is_capped() {
        let budget = Arc::new(ByteBudget::new(1 << 20));
        let admission = Admission::new(&budget, usize::MAX, Duration::from_millis(50));
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut meter = FrameMeter::new(near, admission);
        far.write_all(&vec![b'a'; MAX_UPGRADE + 8]).await.unwrap();
        let mut window = [0u8; 1];
        let mut failed = false;
        for _ in 0..=MAX_UPGRADE {
            if meter.read(&mut window).await.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
    }
}
