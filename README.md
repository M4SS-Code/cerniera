# cerniera

A ZIP archive encoder that never copies your data.

Feed it file content through a `Stream` or write it directly with
`sendfile`, `mmap`, or any I/O strategy you like - cerniera only
encodes the ZIP framing around it.

ZIP64 records are written only where needed: entries over 4 GiB and
archives with more than 65,535 entries are supported.

*Cerniera* (/tʃerˈnjɛːra/) is Italian for *zipper*.

## Quick start

```rust
use std::{io, pin::pin};

use bytes::Bytes;
use cerniera::{FileTimes, MsDosDateTime, ZipEntry, ZipWriter};
use futures_util::{TryStreamExt, stream};
use tokio::{fs::File, io::AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let modified = FileTimes::new(
        MsDosDateTime::new(2026, 3, 10, 12, 30, 0).unwrap(),
        1_773_145_800, // same instant, seconds since 1970-01-01 UTC
    );

    let entries = stream::iter([
        Ok(ZipEntry::file(
            "hello.txt".try_into().unwrap(),
            modified,
            stream::iter([Ok::<_, io::Error>(Bytes::from_static(b"Hello, world!"))]),
        )
        .unwrap()),
        Ok(ZipEntry::directory("subdir/".try_into().unwrap(), modified).unwrap()),
    ]);

    let mut zip_stream = pin!(ZipWriter::new(entries));

    let mut file = File::create("output.zip").await?;
    while let Some(chunk) = zip_stream.try_next().await? {
        file.write_all(&chunk).await?;
    }
    Ok(())
}
```

## Two API levels

- **`ZipWriter`** - high-level streaming builder. Give it entries, get a byte
  stream. Handles CRC-32 and all ZIP bookkeeping automatically. Files are
  stored (uncompressed).

- **`ZipArchive`** - low-level, sans-IO encoder. Gives you full control over
  buffering and compression (DEFLATE, Zstandard, etc.) at the cost of a more
  manual lifecycle. See the [`deflate_zip`](examples/deflate_zip.rs) and
  [`sendfile_zip`](examples/sendfile_zip.rs) examples.

Entry paths are validated on construction: `ZipPath::new` rejects
traversal (`..`), absolute paths, drive letters, colons, backslashes,
and NUL bytes, and the `ZipEntry::file` / `ZipEntry::directory`
constructors enforce the file/directory slash convention - so untrusted
names can be passed straight through the constructors.

That is shape validation, not a universal extraction guarantee: names
like `CON` or `report.` are legal here but can still misbehave in
permissive Windows extractors, and duplicate names are written as-is,
leaving collision resolution to the extractor. Extraction safety
ultimately depends on the reader that unpacks the archive.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | Yes     | Enables runtime SIMD detection for faster CRC-32. Everything works without it. |
| `jiff`  | No      | Adds `TryFrom<jiff::civil::DateTime>` for `MsDosDateTime` and `TryFrom<jiff::Zoned>` for `FileTimes`. |

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
