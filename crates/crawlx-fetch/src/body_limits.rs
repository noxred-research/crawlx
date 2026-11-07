//! Streaming body cap (decompression and oversized-body defence).
//! The cap applies to decoded bytes, so a gzip bomb stops at the limit too.

use crate::error::FetchError;
use crate::tls::HttpResponse;
use bytes::{Bytes, BytesMut};

/// Default cap: 8 MiB.
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Read `resp` into memory, stopping at `max_bytes`. Returns the body and
/// whether it was truncated; the rest of the stream is dropped unread.
pub(crate) async fn read_capped(
    mut resp: HttpResponse,
    max_bytes: usize,
) -> Result<(Bytes, bool), FetchError> {
    let mut buf = BytesMut::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = max_bytes - buf.len();
                if chunk.len() > room {
                    buf.extend_from_slice(&chunk[..room]);
                    return Ok((buf.freeze(), true));
                }
                buf.extend_from_slice(&chunk);
                if buf.len() == max_bytes {
                    // Only clean EOF proves completeness; empty chunks are not EOF.
                    while let Some(chunk) = resp.chunk().await? {
                        if !chunk.is_empty() {
                            return Ok((buf.freeze(), true));
                        }
                    }
                    return Ok((buf.freeze(), false));
                }
            }
            Ok(None) => return Ok((buf.freeze(), false)),
            Err(e) => return Err(e),
        }
    }
}
