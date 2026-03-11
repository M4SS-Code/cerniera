//! Write a ZIP file with DEFLATE compression using the sans-IO API.
//!
//! Run with: `cargo run --example deflate_zip -- file1.txt file2.txt`
//!
//! Compresses each input file with flate2 and writes the result to `output.zip`.
//! Files are read and compressed in streaming chunks, never fully loaded into memory.

use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader, Write},
    process,
};

use bytes::BytesMut;
use cerniera::{CompressionMethod, MsDosDateTime, ZipArchive};
use flate2::{Compression, write::DeflateEncoder};
use jiff::Timestamp;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: deflate_zip <file>...");
        process::exit(1);
    }

    let mut archive = ZipArchive::new();
    let mut buf = BytesMut::new();
    let mut out = File::create("output.zip")?;

    for path in args {
        let src = File::open(&path)?;
        let metadata = src.metadata()?;

        let modified: MsDosDateTime = Timestamp::try_from(metadata.modified()?)
            .expect("modification time out of range")
            .to_zoned(jiff::tz::TimeZone::system())
            .datetime()
            .into();

        archive.start_file(path, modified, CompressionMethod::Deflate, &mut buf);
        out.write_all(&buf)?;
        buf.clear();

        // Stream through the file: feed uncompressed chunks to the archive
        // for CRC tracking, and to the DEFLATE encoder for compression.
        // The encoder writes compressed data directly to the output file.
        let mut encoder =
            DeflateEncoder::new(CountingWriter::new(&mut out), Compression::default());
        let mut reader = BufReader::new(src);
        loop {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                break;
            }
            archive.file_data(buf);
            encoder.write_all(buf)?;
            let len = buf.len();
            reader.consume(len);
        }
        let compressed_size = encoder.finish()?.bytes_written;

        archive.end_file_compressed(compressed_size, &mut buf);
        out.write_all(&buf)?;
        buf.clear();
    }

    archive.finish(&mut buf);
    out.write_all(&buf)?;

    println!("wrote output.zip");
    Ok(())
}

/// A writer wrapper that counts the number of bytes written.
struct CountingWriter<W> {
    inner: W,
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
