//! Shared cancellation-safe byte-stream connection ownership.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, MutexGuard, Notify};
use tokio::time::Instant;

/// One generation of a connection-oriented transport's write side.
///
/// The `Arc` containing this value is also the pool generation token. A
/// receiver may remove a pool entry only when its token is pointer-identical.
pub(crate) struct StreamConnectionIo<W> {
    writer: Mutex<Option<W>>,
    closed: AtomicBool,
    close_notify: Notify,
}

impl<W> StreamConnectionIo<W> {
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(Some(writer)),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Mark this generation unusable and wake its receive loop.
    ///
    /// This is synchronous so every terminal receive or cancelled-write path
    /// closes the generation before it waits for the pool mutex.
    pub(crate) fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.close_notify.notify_one();
        }
    }

    pub(crate) async fn closed(&self) {
        while !self.is_closed() {
            self.close_notify.notified().await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn has_writer(&self) -> bool {
        self.writer.lock().await.is_some()
    }
}

impl<W: AsyncWrite + Unpin> StreamConnectionIo<W> {
    /// Write exactly one record, optionally within an existing absolute
    /// deadline. Cancellation after the write begins poisons this generation.
    pub(crate) async fn write_record(
        &self,
        record: &[u8],
        deadline: Option<Instant>,
    ) -> Result<(), StreamWriteError> {
        let writer = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, self.writer.lock())
                .await
                .map_err(|_| StreamWriteError::LockTimeout)?,
            None => self.writer.lock().await,
        };

        let mut write = RecordWriteGuard::new(self, writer)?;
        let result = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, write.writer().write_all(record))
                .await
                .map_err(|_| StreamWriteError::WriteTimeout),
            None => Ok(write.writer().write_all(record).await),
        };

        match result {
            Ok(Ok(())) => {
                write.commit();
                Ok(())
            }
            Ok(Err(error)) => Err(StreamWriteError::Io(error)),
            Err(error) => Err(error),
        }
    }
}

/// A write failure classified by whether a record could have partially
/// entered the stream.
#[derive(Debug)]
pub(crate) enum StreamWriteError {
    Closed,
    LockTimeout,
    WriteTimeout,
    Io(std::io::Error),
}

impl StreamWriteError {
    pub(crate) fn poisons_connection(&self) -> bool {
        matches!(self, Self::Closed | Self::WriteTimeout | Self::Io(_))
    }
}

impl fmt::Display for StreamWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("stream connection is closed"),
            Self::LockTimeout => formatter.write_str("timed out waiting for stream writer"),
            Self::WriteTimeout => formatter.write_str("stream record write timed out"),
            Self::Io(error) => write!(formatter, "stream record write failed: {error}"),
        }
    }
}

/// Owns the writer mutex from the first write poll until commit.
///
/// Dropping an armed guard means a write future was cancelled, timed out, or
/// failed. The writer half is synchronously removed and dropped before the
/// generation's receiver is notified, so no later record can reuse a stream
/// with an unknown boundary.
struct RecordWriteGuard<'a, W> {
    io: &'a StreamConnectionIo<W>,
    writer: MutexGuard<'a, Option<W>>,
    armed: bool,
}

impl<'a, W> RecordWriteGuard<'a, W> {
    fn new(
        io: &'a StreamConnectionIo<W>,
        mut writer: MutexGuard<'a, Option<W>>,
    ) -> Result<Self, StreamWriteError> {
        if io.is_closed() || writer.is_none() {
            writer.take();
            io.mark_closed();
            return Err(StreamWriteError::Closed);
        }
        Ok(Self {
            io,
            writer,
            armed: true,
        })
    }

    fn writer(&mut self) -> &mut W {
        self.writer
            .as_mut()
            .expect("armed record writer must own a write half")
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

impl<W> Drop for RecordWriteGuard<'_, W> {
    fn drop(&mut self) {
        if self.armed {
            self.writer.take();
            self.io.mark_closed();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;

    use super::*;

    #[tokio::test]
    async fn abort_after_partial_progress_drops_writer_and_successor_is_clean() {
        let (writer, mut reader) = tokio::io::duplex(1);
        let io = Arc::new(StreamConnectionIo::new(writer));
        let cancelled_io = io.clone();
        let record = vec![0x5a; 64];
        let send = tokio::spawn(async move { cancelled_io.write_record(&record, None).await });

        let mut first = [0u8; 1];
        reader.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [0x5a], "one byte proves partial stream progress");
        assert!(
            !send.is_finished(),
            "the bounded stream cannot hold the record"
        );
        send.abort();
        assert!(send.await.unwrap_err().is_cancelled());

        tokio::time::timeout(Duration::from_secs(1), io.closed())
            .await
            .expect("cancelled write must synchronously signal closure");
        assert!(io.is_closed());
        assert!(!io.has_writer().await);

        let clean_record = b"complete successor record".to_vec();
        let (writer, mut reader) = tokio::io::duplex(clean_record.len());
        let successor = StreamConnectionIo::new(writer);
        successor.write_record(&clean_record, None).await.unwrap();
        let mut received = vec![0u8; clean_record.len()];
        reader.read_exact(&mut received).await.unwrap();
        assert_eq!(received, clean_record);
        assert!(!successor.is_closed());
    }
}
