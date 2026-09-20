//! `ZipEntry` constructor validation: the trailing-slash convention is
//! enforced at construction, so a path that validates can no longer
//! panic the writer.

use std::io;

use bytes::Bytes;
use cerniera::{FileTimes, InvalidZipPath, ZipEntry};
use futures_util::stream;

/// A concrete content-stream type. Directory entries carry no content,
/// so constructing one standalone needs the stream's `S` spelled out;
/// in a mixed entry stream it is inferred from the file entries.
type Content = stream::Iter<std::iter::Empty<Result<Bytes, io::Error>>>;

fn empty_content() -> Content {
    stream::iter(std::iter::empty::<Result<Bytes, io::Error>>())
}

#[test]
fn file_constructor_rejects_trailing_slash() {
    let path = "dir/".try_into().unwrap();
    assert!(matches!(
        ZipEntry::file(path, FileTimes::default(), empty_content()),
        Err(InvalidZipPath::FileWithTrailingSlash(p)) if p == "dir/"
    ));
}

#[test]
fn directory_constructor_requires_trailing_slash() {
    let path = "dir".try_into().unwrap();
    assert!(matches!(
        ZipEntry::<Content>::directory(path, FileTimes::default()),
        Err(InvalidZipPath::DirectoryWithoutSlash(p)) if p == "dir"
    ));
}

#[test]
fn constructors_accept_matching_paths() {
    assert!(
        ZipEntry::file(
            "images/photo.jpg".try_into().unwrap(),
            FileTimes::default(),
            empty_content(),
        )
        .is_ok()
    );
    assert!(
        ZipEntry::<Content>::directory("subdir/".try_into().unwrap(), FileTimes::default()).is_ok()
    );
}
