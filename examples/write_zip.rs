//! Write a ZIP file to disk using `ZipWriter` with tokio.
//!
//! Run with: `cargo run --example write_zip`
//!
//! Creates `output.zip` containing two files and a directory.

use std::{io, pin::pin};

use bytes::Bytes;
use cerniera::{MsDosDateTime, ZipEntry, ZipWriter};
use futures_util::{TryStreamExt, stream};
use tokio::{fs::File, io::AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let modified = MsDosDateTime::new(2026, 3, 10, 12, 30, 0);

    let entries: Vec<io::Result<_>> = vec![
        Ok(ZipEntry::File {
            path: "hello.txt".into(),
            modified,
            content: stream::iter([Ok(Bytes::from_static(b"Hello, world!"))]),
        }),
        Ok(ZipEntry::Directory {
            path: "subdir/".into(),
            modified,
        }),
        Ok(ZipEntry::File {
            path: "subdir/notes.txt".into(),
            modified,
            content: stream::iter([Ok(Bytes::from_static(b"Some notes in a subdir.\n"))]),
        }),
    ];

    let mut zip_stream = pin!(ZipWriter::new(stream::iter(entries)));

    let mut file = File::create("output.zip").await?;
    while let Some(chunk) = zip_stream.try_next().await? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    println!("wrote output.zip");
    Ok(())
}
