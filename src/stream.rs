use core::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use pin_project_lite::pin_project;

use crate::archive::{CompressionMethod, FileTimes, InvalidZipPath, ZipArchive, ZipPath};

/// One entry (file or directory) passed to [`ZipWriter`].
///
/// Entries are created with the fallible constructors
/// [`file`](Self::file) and [`directory`](Self::directory), which
/// validate the trailing-slash convention up front: a file path must
/// not end with `'/'`, a directory path must - extractors classify an
/// entry by its trailing slash, so a mismatch would produce headers
/// that disagree.
pub struct ZipEntry<S> {
    inner: EntryInner<S>,
}

/// The kind of a [`ZipEntry`]; created only by the constructors, which
/// validate the kind/path match before any header is written.
enum EntryInner<S> {
    /// A file entry.
    File {
        /// Path inside the archive, e.g. `"images/photo.jpg"`.
        path: ZipPath,
        /// Last-modified date and time.
        modified: FileTimes,
        /// Raw byte stream.
        content: S,
    },
    /// A directory entry.
    Directory {
        /// Path inside the archive, e.g. `"subdir/"`.
        path: ZipPath,
        /// Last-modified date and time.
        modified: FileTimes,
    },
}

impl<S> ZipEntry<S> {
    /// Create a file entry.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidZipPath::FileWithTrailingSlash`] when `path`
    /// ends with `'/'` - that shape names a directory; use
    /// [`directory`](Self::directory) instead.
    pub fn file(path: ZipPath, modified: FileTimes, content: S) -> Result<Self, InvalidZipPath> {
        if path.as_str().ends_with('/') {
            return Err(InvalidZipPath::FileWithTrailingSlash(path.into_inner()));
        }
        Ok(Self {
            inner: EntryInner::File {
                path,
                modified,
                content,
            },
        })
    }

    /// Create a directory entry.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidZipPath::DirectoryWithoutSlash`] when `path`
    /// does not end with `'/'` - extractors classify an entry as a
    /// directory by its trailing slash.
    pub fn directory(path: ZipPath, modified: FileTimes) -> Result<Self, InvalidZipPath> {
        if !path.as_str().ends_with('/') {
            return Err(InvalidZipPath::DirectoryWithoutSlash(path.into_inner()));
        }
        Ok(Self {
            inner: EntryInner::Directory { path, modified },
        })
    }
}

pin_project! {
    /// High-level streaming ZIP archive builder.
    ///
    /// Wraps a stream of [`ZipEntry`] items and produces a
    /// `Stream<Item = Result<Bytes, E>>` of ZIP-encoded bytes. Files are
    /// stored (uncompressed); CRC-32 checksums and all ZIP bookkeeping are
    /// handled automatically.
    ///
    /// Errors are terminal: when an entry's content stream or the entry
    /// list yields an `Err`, the error is surfaced once and the stream
    /// yields `None` on every later poll. A content error can arrive
    /// mid-entry, when the archive already holds a partial record, so the
    /// stream can no longer produce a valid archive afterwards.
    ///
    /// # Memory
    ///
    /// Every entry's metadata (path and bookkeeping, on the order of
    /// 100 bytes) is retained until the entry stream ends, and the
    /// central directory is then encoded into a single final chunk -
    /// one large allocation and one long poll, regardless of downstream
    /// backpressure. If the entry list comes from untrusted input, bound
    /// the entry count (and total size) before feeding it.
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
    #[must_use]
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

                Poll::Ready(Some(Err(e))) => {
                    // Terminal: a content error can arrive mid-entry, when
                    // the archive already holds a partial record, so no
                    // valid archive can be produced afterwards. Drop the
                    // content stream, yield the error once, then end.
                    *this.done = true;
                    this.current_stream.set(None);
                    Poll::Ready(Some(Err(e)))
                }

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

                Poll::Ready(Some(Err(e))) => {
                    // Terminal, like content errors: yield the error once,
                    // then end.
                    *this.done = true;
                    Poll::Ready(Some(Err(e)))
                }

                Poll::Ready(Some(Ok(entry))) => match entry.inner {
                    EntryInner::File {
                        path,
                        modified,
                        content,
                    } => {
                        this.archive.start_file(
                            path,
                            modified,
                            CompressionMethod::Stored,
                            this.buf,
                        );
                        this.current_stream.set(Some(content));
                        Poll::Ready(Some(Ok(this.buf.split().freeze())))
                    }
                    EntryInner::Directory { path, modified } => {
                        this.archive.add_directory(path, modified, this.buf);
                        Poll::Ready(Some(Ok(this.buf.split().freeze())))
                    }
                },

                Poll::Ready(None) => {
                    this.archive.finish(this.buf);
                    *this.done = true;
                    Poll::Ready(Some(Ok(this.buf.split().freeze())))
                }
            }
        }
    }
}
