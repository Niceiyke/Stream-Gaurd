//! Generic bounded framing for V2 reliable control streams.
//!
//! The caller supplies an already-authenticated `AsyncRead`/`AsyncWrite`.
//! This module deliberately has no Quinn types and does not open streams.

use sg_protocol::v2::control::{ControlCodecError, ControlFrame, ControlFrameLimit};
use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Deadlines covering an entire incomplete frame read or write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlDeadlines {
    pub read: Duration,
    pub write: Duration,
}

impl Default for ControlDeadlines {
    fn default() -> Self {
        Self {
            read: Duration::from_secs(5),
            write: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Error)]
pub enum ControlStreamError {
    #[error("V2 control stream is terminal after an earlier framing failure")]
    Poisoned,
    #[error("V2 control read deadline elapsed")]
    ReadDeadline,
    #[error("V2 control write deadline elapsed")]
    WriteDeadline,
    #[error("V2 stream control frame length {length} exceeds limit {limit}")]
    FrameTooLarge { length: usize, limit: usize },
    #[error("V2 control stream I/O error: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Codec(#[from] ControlCodecError),
}

/// Length-prefix adapter for one ordered reliable control stream. Prefixes are
/// four-byte big-endian lengths for the complete `sg_protocol` control frame.
pub struct ControlFramed<S> {
    io: S,
    limit: ControlFrameLimit,
    deadlines: ControlDeadlines,
    poisoned: bool,
}

impl<S> ControlFramed<S> {
    pub const fn new(io: S, limit: ControlFrameLimit, deadlines: ControlDeadlines) -> Self {
        Self {
            io,
            limit,
            deadlines,
            poisoned: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.io
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

impl<S: AsyncRead + Unpin> ControlFramed<S> {
    /// Reads exactly one bounded frame. The advertised length is checked before
    /// allocating the frame buffer, and both prefix and body share one deadline.
    pub async fn read_frame(&mut self) -> Result<ControlFrame, ControlStreamError> {
        if self.poisoned {
            return Err(ControlStreamError::Poisoned);
        }
        let mut prefix = [0u8; 4];
        let limit = self.limit.maximum();
        let read = async {
            self.io.read_exact(&mut prefix).await?;
            let length = u32::from_be_bytes(prefix) as usize;
            if length > limit {
                return Err(ControlStreamError::FrameTooLarge { length, limit });
            }
            let mut frame = vec![0u8; length];
            self.io.read_exact(&mut frame).await?;
            ControlFrame::decode(&frame, self.limit).map_err(ControlStreamError::from)
        };
        match tokio::time::timeout(self.deadlines.read, read).await {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(error)) => {
                self.poisoned = true;
                Err(error)
            }
            Err(_) => {
                self.poisoned = true;
                Err(ControlStreamError::ReadDeadline)
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> ControlFramed<S> {
    /// Encodes and writes exactly one bounded frame plus its big-endian length
    /// prefix. A stalled peer cannot hold the write operation indefinitely.
    pub async fn write_frame(&mut self, frame: &ControlFrame) -> Result<(), ControlStreamError> {
        if self.poisoned {
            return Err(ControlStreamError::Poisoned);
        }
        let encoded = match frame.encode(self.limit) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let length = match u32::try_from(encoded.len()) {
            Ok(length) => length,
            Err(_) => {
                self.poisoned = true;
                return Err(ControlStreamError::FrameTooLarge {
                    length: encoded.len(),
                    limit: u32::MAX as usize,
                });
            }
        };
        let write = async {
            self.io.write_all(&length.to_be_bytes()).await?;
            self.io.write_all(&encoded).await?;
            self.io.flush().await?;
            Ok::<(), io::Error>(())
        };
        match tokio::time::timeout(self.deadlines.write, write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                self.poisoned = true;
                Err(error.into())
            }
            Err(_) => {
                self.poisoned = true;
                Err(ControlStreamError::WriteDeadline)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_core::v2::DeviceId;
    use sg_protocol::v2::control::{AdmissionTicket, ControlMessage};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    fn frame() -> ControlFrame {
        ControlFrame {
            transaction_id: 1,
            message: ControlMessage::ClientHello {
                device_id: DeviceId::from_bytes([0x11; 16]),
                requested_gateway: "iad-1".into(),
                ticket: AdmissionTicket::new("ticket".into()).unwrap(),
            },
        }
    }

    fn framed(io: DuplexStream) -> ControlFramed<DuplexStream> {
        ControlFramed::new(
            io,
            ControlFrameLimit::default(),
            ControlDeadlines::default(),
        )
    }

    #[tokio::test]
    async fn generic_duplex_stream_round_trips_one_exact_frame() {
        let (left, right) = tokio::io::duplex(1024);
        let mut writer = framed(left);
        let mut reader = framed(right);
        let expected = frame();
        writer.write_frame(&expected).await.unwrap();
        assert_eq!(reader.read_frame().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn oversized_prefix_is_rejected_before_body_allocation_and_poisoned() {
        let (mut writer, reader) = tokio::io::duplex(16);
        writer.write_all(&1024u32.to_be_bytes()).await.unwrap();
        let mut framed = ControlFramed::new(
            reader,
            ControlFrameLimit::new(128),
            ControlDeadlines::default(),
        );
        assert!(matches!(
            framed.read_frame().await,
            Err(ControlStreamError::FrameTooLarge {
                length: 1024,
                limit: 128,
            })
        ));
        assert!(framed.is_poisoned());
        assert!(matches!(framed.read_frame().await, Err(ControlStreamError::Poisoned)));
    }

    #[tokio::test]
    async fn malformed_codec_frame_poisoned_the_stream() {
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(&16u32.to_be_bytes()).await.unwrap();
        writer.write_all(&[0; 16]).await.unwrap();
        let mut framed = ControlFramed::new(
            reader,
            ControlFrameLimit::default(),
            ControlDeadlines::default(),
        );
        assert!(matches!(
            framed.read_frame().await,
            Err(ControlStreamError::Codec(ControlCodecError::UnsupportedVersion(0)))
        ));
        assert!(framed.is_poisoned());
        assert!(matches!(framed.read_frame().await, Err(ControlStreamError::Poisoned)));
    }

    struct PendingReader;

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    struct ErrorReader;

    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "test error")))
        }
    }

    #[tokio::test]
    async fn incomplete_read_observes_terminal_deadline_without_sleeping() {
        let mut framed = ControlFramed::new(
            PendingReader,
            ControlFrameLimit::default(),
            ControlDeadlines {
                read: Duration::ZERO,
                write: Duration::from_secs(1),
            },
        );
        assert!(matches!(framed.read_frame().await, Err(ControlStreamError::ReadDeadline)));
        assert!(framed.is_poisoned());
        assert!(matches!(framed.read_frame().await, Err(ControlStreamError::Poisoned)));
    }

    #[tokio::test]
    async fn read_io_error_poisoned_the_stream() {
        let mut framed = ControlFramed::new(
            ErrorReader,
            ControlFrameLimit::default(),
            ControlDeadlines::default(),
        );
        assert!(matches!(framed.read_frame().await, Err(ControlStreamError::Io(_))));
        assert!(framed.is_poisoned());
        assert!(matches!(framed.read_frame().await, Err(ControlStreamError::Poisoned)));
    }

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct PartialErrorWriter {
        wrote_once: bool,
    }

    impl AsyncWrite for PartialErrorWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.wrote_once {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "test error")));
            }
            self.wrote_once = true;
            Poll::Ready(Ok(buffer.len().min(1)))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn incomplete_write_observes_terminal_deadline_without_sleeping() {
        let mut framed = ControlFramed::new(
            PendingWriter,
            ControlFrameLimit::default(),
            ControlDeadlines {
                read: Duration::from_secs(1),
                write: Duration::ZERO,
            },
        );
        assert!(matches!(
            framed.write_frame(&frame()).await,
            Err(ControlStreamError::WriteDeadline)
        ));
        assert!(framed.is_poisoned());
        assert!(matches!(
            framed.write_frame(&frame()).await,
            Err(ControlStreamError::Poisoned)
        ));
    }

    #[tokio::test]
    async fn partial_write_error_poisoned_the_stream() {
        let mut framed = ControlFramed::new(
            PartialErrorWriter { wrote_once: false },
            ControlFrameLimit::default(),
            ControlDeadlines::default(),
        );
        assert!(matches!(framed.write_frame(&frame()).await, Err(ControlStreamError::Io(_))));
        assert!(framed.is_poisoned());
        assert!(matches!(
            framed.write_frame(&frame()).await,
            Err(ControlStreamError::Poisoned)
        ));
    }
}
