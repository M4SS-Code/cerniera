//! `ZipWriter` stream behavior: errors are terminal.

use std::{io, pin::pin};

use bytes::Bytes;
use cerniera::{FileTimes, ZipEntry, ZipWriter};
use futures_util::{StreamExt, stream};

fn boom() -> io::Error {
    io::Error::other("boom")
}

#[tokio::test]
async fn content_stream_error_is_terminal() {
    let entries = stream::iter([Ok(ZipEntry::file(
        "a.txt".try_into().unwrap(),
        FileTimes::default(),
        stream::iter([Ok(Bytes::from_static(b"hi")), Err(boom())]),
    )
    .unwrap())]);

    let mut zip = pin!(ZipWriter::new(entries));

    // Local header chunk, then the data chunk.
    assert!(zip.next().await.unwrap().is_ok());
    assert!(zip.next().await.unwrap().is_ok());

    // The error surfaces exactly once...
    assert!(matches!(zip.next().await, Some(Err(_))));

    // ...then the stream is done: polling again must yield None rather
    // than keep the half-finished entry active, which would panic on the
    // next entry's start_file.
    assert!(zip.next().await.is_none());
}

#[tokio::test]
async fn entries_stream_error_is_terminal() {
    let entries = stream::iter([
        Ok(ZipEntry::file(
            "a.txt".try_into().unwrap(),
            FileTimes::default(),
            stream::iter([Ok(Bytes::from_static(b"x"))]),
        )
        .unwrap()),
        Err(boom()),
    ]);

    let mut zip = pin!(ZipWriter::new(entries));
    // Drain the first entry: header chunk, data chunk, descriptor chunk.
    assert!(zip.next().await.unwrap().is_ok());
    assert!(zip.next().await.unwrap().is_ok());
    assert!(zip.next().await.unwrap().is_ok());
    assert!(matches!(zip.next().await, Some(Err(_))));
    assert!(zip.next().await.is_none());
}
