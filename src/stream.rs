use alloc::string::String;
use core::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use pin_project_lite::pin_project;

use crate::archive::{CompressionMethod, MsDosDateTime, ZipArchive};

/// One entry (file or directory) passed to [`ZipWriter`].
pub enum ZipEntry<S> {
    /// A file entry.
    File {
        /// Path inside the archive, e.g. `"images/photo.jpg"`.
        path: String,
        /// Last-modified date and time.
        modified: MsDosDateTime,
        /// Raw byte stream.
        content: S,
    },
    /// A directory entry. `path` should end with `'/'`.
    Directory {
        /// Path inside the archive, e.g. `"subdir/"`.
        path: String,
        /// Last-modified date and time.
        modified: MsDosDateTime,
    },
}

pin_project! {
    /// High-level streaming ZIP archive builder.
    ///
    /// Wraps a stream of [`ZipEntry`] items and produces a
    /// `Stream<Item = Result<Bytes, E>>` of ZIP-encoded bytes. Files are
    /// stored (uncompressed); CRC-32 checksums and all ZIP bookkeeping are
    /// handled automatically.
    ///
    /// For compressed output or custom I/O, use [`ZipArchive`] directly.
    ///
    /// See the [crate-level docs](crate) for a full example.
    pub struct ZipWriter<I, S> {
        #[pin]
        current_stream: Option<S>,
        #[pin]
        entries: I,
        archive: ZipArchive,
        buf: BytesMut,
        done: bool,
    }
}

impl<I, S, E> ZipWriter<I, S>
where
    I: Stream<Item = Result<ZipEntry<S>, E>>,
    S: Stream<Item = Result<Bytes, E>>,
{
    pub fn new(entries: I) -> Self {
        Self {
            current_stream: None,
            entries,
            archive: ZipArchive::new(),
            buf: BytesMut::new(),
            done: false,
        }
    }
}

impl<I, S, E> Stream for ZipWriter<I, S>
where
    I: Stream<Item = Result<ZipEntry<S>, E>>,
    S: Stream<Item = Result<Bytes, E>>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        debug_assert!(this.buf.is_empty());
        if *this.done {
            return Poll::Ready(None);
        }

        if let Some(stream) = this.current_stream.as_mut().as_pin_mut() {
            match stream.poll_next(cx) {
                Poll::Pending => Poll::Pending,

                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),

                Poll::Ready(Some(Ok(chunk))) => {
                    this.archive.file_data(&chunk);
                    Poll::Ready(Some(Ok(chunk)))
                }

                Poll::Ready(None) => {
                    this.current_stream.set(None);
                    this.archive.end_file(this.buf);
                    Poll::Ready(Some(Ok(this.buf.split().freeze())))
                }
            }
        } else {
            match this.entries.as_mut().poll_next(cx) {
                Poll::Pending => Poll::Pending,

                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),

                Poll::Ready(Some(Ok(ZipEntry::File {
                    path,
                    modified,
                    content,
                }))) => {
                    this.archive
                        .start_file(path, modified, CompressionMethod::Stored, this.buf);
                    this.current_stream.set(Some(content));
                    Poll::Ready(Some(Ok(this.buf.split().freeze())))
                }

                Poll::Ready(Some(Ok(ZipEntry::Directory { path, modified }))) => {
                    this.archive.add_directory(path, modified, this.buf);
                    Poll::Ready(Some(Ok(this.buf.split().freeze())))
                }

                Poll::Ready(None) => {
                    this.archive.finish(this.buf);
                    *this.done = true;
                    Poll::Ready(Some(Ok(this.buf.split().freeze())))
                }
            }
        }
    }
}
