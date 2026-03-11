//! Round-trip tests: generate archives with cerniera, read them back with the `zip` crate.

use std::io::{Cursor, Read};

use bytes::BytesMut;
use cerniera::{CompressionMethod, MsDosDateTime, ZipArchive};

/// Helper: collect all `ZipArchive` output into a flat `Vec<u8>`.
fn build_archive(f: impl FnOnce(&mut ZipArchive, &mut BytesMut, &mut Vec<u8>)) -> Vec<u8> {
    let mut archive = ZipArchive::new();
    let mut buf = BytesMut::new();
    let mut out = Vec::new();
    f(&mut archive, &mut buf, &mut out);
    archive.finish(&mut buf);
    out.extend_from_slice(&buf);
    out
}

fn flush(buf: &mut BytesMut, out: &mut Vec<u8>) {
    out.extend_from_slice(buf);
    buf.clear();
}

#[test]
fn empty_archive() {
    let zip_bytes = build_archive(|_, _, _| {});
    let reader = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    assert_eq!(reader.len(), 0);
}

#[test]
fn single_stored_file() {
    let content = b"Hello, cerniera!";
    let modified = MsDosDateTime::new(2026, 3, 10, 12, 30, 0);

    let zip_bytes = build_archive(|archive, buf, out| {
        archive.start_file("hello.txt".into(), modified, CompressionMethod::Stored, buf);
        flush(buf, out);

        archive.file_data(content);
        out.extend_from_slice(content);

        archive.end_file(buf);
        flush(buf, out);
    });

    let mut reader = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    assert_eq!(reader.len(), 1);

    let mut file = reader.by_name("hello.txt").unwrap();
    assert_eq!(file.compression(), zip::CompressionMethod::Stored);
    assert_eq!(file.size(), content.len() as u64);

    let mut read_back = Vec::new();
    file.read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, content);
}

#[test]
fn multiple_files_and_directory() {
    let modified = MsDosDateTime::new(2026, 3, 10, 14, 0, 0);

    let zip_bytes = build_archive(|archive, buf, out| {
        // Directory
        archive.add_directory("subdir/".into(), modified, buf);
        flush(buf, out);

        // First file
        let a = b"file a contents";
        archive.start_file("a.txt".into(), modified, CompressionMethod::Stored, buf);
        flush(buf, out);
        archive.file_data(a);
        out.extend_from_slice(a);
        archive.end_file(buf);
        flush(buf, out);

        // Second file in subdir
        let b = b"file b contents here";
        archive.start_file(
            "subdir/b.txt".into(),
            modified,
            CompressionMethod::Stored,
            buf,
        );
        flush(buf, out);
        archive.file_data(b);
        out.extend_from_slice(b);
        archive.end_file(buf);
        flush(buf, out);
    });

    let mut reader = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    assert_eq!(reader.len(), 3);

    // Directory
    let dir = reader.by_name("subdir/").unwrap();
    assert!(dir.is_dir());
    drop(dir);

    // File a
    let mut file_a = reader.by_name("a.txt").unwrap();
    let mut a_data = Vec::new();
    file_a.read_to_end(&mut a_data).unwrap();
    assert_eq!(a_data, b"file a contents");
    drop(file_a);

    // File b
    let mut file_b = reader.by_name("subdir/b.txt").unwrap();
    let mut b_data = Vec::new();
    file_b.read_to_end(&mut b_data).unwrap();
    assert_eq!(b_data, b"file b contents here");
}

#[test]
fn deflate_compressed_file() {
    use flate2::{Compression, write::DeflateEncoder};
    use std::io::Write;

    let content = b"the quick brown fox jumps over the lazy dog, again and again and again";
    let modified = MsDosDateTime::new(2026, 3, 10, 16, 0, 0);

    let zip_bytes = build_archive(|archive, buf, out| {
        archive.start_file(
            "compressed.txt".into(),
            modified,
            CompressionMethod::Deflate,
            buf,
        );
        flush(buf, out);

        // Feed uncompressed data for CRC tracking
        archive.file_data(content);

        // Compress and write to output
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).unwrap();
        let compressed = encoder.finish().unwrap();
        out.extend_from_slice(&compressed);

        archive.end_file_compressed(compressed.len() as u64, buf);
        flush(buf, out);
    });

    let mut reader = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    assert_eq!(reader.len(), 1);

    let mut file = reader.by_name("compressed.txt").unwrap();
    assert_eq!(file.compression(), zip::CompressionMethod::Deflated);
    assert_eq!(file.size(), content.len() as u64);

    let mut read_back = Vec::new();
    file.read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, content);
}
