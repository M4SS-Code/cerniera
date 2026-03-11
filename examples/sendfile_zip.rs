//! Write a ZIP file using mmap for checksums and sendfile for data transfer.
//!
//! Run with: `cargo run --example sendfile_zip -- file1.txt file2.txt`
//!
//! Uses the sans-IO `ZipArchive` API directly. Linux only.

use std::{env, fs::File, io, io::Write, process};

use bytes::BytesMut;
use cerniera::{CompressionMethod, MsDosDateTime, ZipArchive};
use jiff::{Timestamp, tz::TimeZone};
use memmap2::Mmap;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: sendfile_zip <file>...");
        process::exit(1);
    }

    let mut archive = ZipArchive::new();
    let mut buf = BytesMut::new();
    let mut out = File::create("output.zip")?;

    for path in args {
        let src = File::open(&path)?;
        let metadata = src.metadata()?;
        let len = metadata.len();

        let modified: MsDosDateTime = Timestamp::try_from(metadata.modified()?)
            .expect("modification time out of range")
            .to_zoned(TimeZone::system())
            .datetime()
            .into();

        archive.start_file(path, modified, CompressionMethod::Stored, &mut buf);
        out.write_all(&buf)?;
        buf.clear();

        // Compute CRC from the memory-mapped region.

        {
            // SAFETY: the file is open and not modified while mapped.
            #[expect(unsafe_code, reason = "mmap requires unsafe")]
            let mmap = unsafe { Mmap::map(&src)? };
            archive.file_data(&mmap);
        }

        // Transfer file data kernel-to-kernel via sendfile.
        let mut offset: i64 = 0;
        let mut remaining = len;
        while remaining > 0 {
            let chunk = usize::try_from(remaining).unwrap_or(usize::MAX);
            let n = nix::sys::sendfile::sendfile(&out, &src, Some(&mut offset), chunk)
                .map_err(io::Error::from)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "sendfile wrote 0 bytes",
                ));
            }
            remaining -= n as u64;
        }

        archive.end_file(&mut buf);
        out.write_all(&buf)?;
        buf.clear();
    }

    archive.finish(&mut buf);
    out.write_all(&buf)?;

    println!("wrote output.zip");
    Ok(())
}
