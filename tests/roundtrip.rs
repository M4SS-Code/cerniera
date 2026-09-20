//! Round-trip tests: generate archives with cerniera, read them back with the `zip` crate.

use std::{
    io::{Cursor, Read},
    pin::pin,
};

use bytes::{Bytes, BytesMut};
use cerniera::{CompressionMethod, FileTimes, MsDosDateTime, ZipArchive, ZipEntry, ZipWriter};

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
    let modified = FileTimes::new(
        MsDosDateTime::new(2026, 3, 10, 12, 30, 0).unwrap(),
        1_773_145_800,
    );

    let zip_bytes = build_archive(|archive, buf, out| {
        archive.start_file(
            "hello.txt".try_into().unwrap(),
            modified,
            CompressionMethod::Stored,
            buf,
        );
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

    // The Unix timestamp round-trips as an extended timestamp extra field.
    assert!(
        file.extra_data_fields()
            .any(|f| matches!(f, zip::extra_fields::ExtraField::ExtendedTimestamp(_))),
        "expected an extended timestamp extra field"
    );
}

#[test]
fn multiple_files_and_directory() {
    let modified = FileTimes::dos_only(MsDosDateTime::new(2026, 3, 10, 14, 0, 0).unwrap());

    let zip_bytes = build_archive(|archive, buf, out| {
        // Directory
        archive.add_directory("subdir/".try_into().unwrap(), modified, buf);
        flush(buf, out);

        // First file
        let a = b"file a contents";
        archive.start_file(
            "a.txt".try_into().unwrap(),
            modified,
            CompressionMethod::Stored,
            buf,
        );
        flush(buf, out);
        archive.file_data(a);
        out.extend_from_slice(a);
        archive.end_file(buf);
        flush(buf, out);

        // Second file in subdir
        let b = b"file b contents here";
        archive.start_file(
            "subdir/b.txt".try_into().unwrap(),
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
    let modified = FileTimes::dos_only(MsDosDateTime::new(2026, 3, 10, 16, 0, 0).unwrap());

    let zip_bytes = build_archive(|archive, buf, out| {
        archive.start_file(
            "compressed.txt".try_into().unwrap(),
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

#[test]
fn zero_length_file() {
    // A stored file with no data: descriptor carries 0/0 and crc 0.
    let zip_bytes = build_archive(|archive, buf, out| {
        archive.start_file(
            "empty.txt".try_into().unwrap(),
            FileTimes::default(),
            CompressionMethod::Stored,
            buf,
        );
        flush(buf, out);
        archive.end_file(buf);
        flush(buf, out);
    });

    let mut reader = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    assert_eq!(reader.len(), 1);
    let mut file = reader.by_name("empty.txt").unwrap();
    assert_eq!(file.size(), 0);
    let mut read_back = Vec::new();
    file.read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back.len(), 0);
}

#[test]
fn zip64_eocd_roundtrip_65_535_entries() {
    // Exactly 65,535 entries: the plain EOCD's count field would carry
    // the 0xFFFF sentinel, so a ZIP64 EOCD record and locator are
    // required. Round-trip through the reference reader at the exact
    // boundary.
    let n: u32 = 65_535;
    let zip_bytes = build_archive(|archive, buf, out| {
        for i in 0..n {
            let name = format!("e{i:05}.txt");
            archive.start_file(
                name.clone().try_into().unwrap(),
                FileTimes::default(),
                CompressionMethod::Stored,
                buf,
            );
            flush(buf, out);
            archive.file_data(b"abcd");
            out.extend_from_slice(b"abcd");
            archive.end_file(buf);
            flush(buf, out);
        }
    });

    let mut reader = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    assert_eq!(reader.len(), n as usize);
    let mut file = reader.by_name("e00000.txt").unwrap();
    let mut read_back = Vec::new();
    file.read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, b"abcd");
}

// A fabricated 4 GiB entry cannot be round-tripped: its declared sizes
// make the logical CD/EOCD offsets point past the physical end of the
// file, and the reference reader rejects the archive. The 8-byte data
// descriptor and ZIP64 CD-extra encodings stay covered by the unit
// tests in src/archive.rs, and the entry-count test above covers the
// ZIP64 EOCD path end to end.

#[tokio::test]
async fn zip_writer_roundtrip() {
    // High-level path: fallible constructors + ZipWriter, read back
    // with the reference reader.
    use futures_util::{StreamExt, stream};

    let modified = FileTimes::new(
        MsDosDateTime::new(2026, 3, 10, 12, 30, 0).unwrap(),
        1_773_145_800,
    );

    let entries = stream::iter([
        Ok(ZipEntry::file(
            "hello.txt".try_into().unwrap(),
            modified,
            stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
                b"Hello, cerniera!",
            ))]),
        )
        .unwrap()),
        Ok(ZipEntry::directory("subdir/".try_into().unwrap(), modified).unwrap()),
    ]);

    let mut writer = pin!(ZipWriter::new(entries));
    let mut out = Vec::new();
    while let Some(chunk) = writer.next().await {
        out.extend_from_slice(&chunk.unwrap());
    }

    let mut reader = zip::ZipArchive::new(Cursor::new(out)).unwrap();
    assert_eq!(reader.len(), 2);

    let mut read_back = Vec::new();
    {
        let mut file = reader.by_name("hello.txt").unwrap();
        file.read_to_end(&mut read_back).unwrap();
    }
    assert_eq!(read_back, b"Hello, cerniera!");

    let dir = reader.by_name("subdir/").unwrap();
    assert!(!dir.is_file());
}
