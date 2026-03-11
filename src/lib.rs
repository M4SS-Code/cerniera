//! A ZIP archive encoder that never copies your data.
//!
//! Feed it file content through a [`Stream`](futures_core::Stream) or
//! write it directly with `sendfile`, `mmap`, or any I/O strategy you
//! like - cerniera only encodes the ZIP framing around it.
//!
//! *Cerniera* (/t∫erˈnjɛra/) is Italian for *zipper*.
//!
//! # Quick start
//!
//! Feed a stream of [`ZipEntry`] items to [`ZipWriter`] and you get back a
//! byte stream you can write to a file, use as an HTTP response body, or
//! forward anywhere that accepts a `Stream`.
//!
//! ```rust,no_run
//! use std::{io, pin::pin};
//!
//! use bytes::Bytes;
//! use cerniera::{MsDosDateTime, ZipEntry, ZipWriter};
//! use futures_util::{TryStreamExt, stream};
//! use tokio::{fs::File, io::AsyncWriteExt};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> io::Result<()> {
//! let modified = MsDosDateTime::new(2026, 3, 10, 12, 30, 0);
//!
//! let entries = stream::iter([
//!     Ok(ZipEntry::File {
//!         path: "hello.txt".into(),
//!         modified,
//!         content: stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"Hello, world!"))]),
//!     }),
//!     Ok(ZipEntry::Directory {
//!         path: "subdir/".into(),
//!         modified,
//!     }),
//! ]);
//!
//! let mut zip_stream = pin!(ZipWriter::new(entries));
//!
//! let mut file = File::create("output.zip").await?;
//! while let Some(chunk) = zip_stream.try_next().await? {
//!     file.write_all(&chunk).await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Two API levels
//!
//! - **[`ZipWriter`]** - high-level streaming builder. Give it entries, get a
//!   byte stream. Handles CRC-32 and all ZIP bookkeeping automatically.
//!   Files are stored (uncompressed).
//!
//! - **[`ZipArchive`]** - low-level, sans-IO encoder. Gives you full control
//!   over buffering and compression (DEFLATE, Zstandard, etc.) at the cost of
//!   a more manual lifecycle. See the `deflate_zip` and `sendfile_zip`
//!   examples.
//!
//! # Features
//!
//! - **`std`** *(default)* - enables runtime SIMD detection for faster CRC-32.
//! - **`jiff`** - adds `From<jiff::civil::DateTime>` for [`MsDosDateTime`].

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod archive;
mod stream;

pub use self::archive::{CompressionMethod, MsDosDateTime, ZipArchive};
pub use self::stream::{ZipEntry, ZipWriter};
