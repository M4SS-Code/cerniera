# cerniera

A ZIP archive encoder that never copies your data.

Feed it file content through a `Stream` or write it directly with
`sendfile`, `mmap`, or any I/O strategy you like - cerniera only
encodes the ZIP framing around it.

*Cerniera* (/t∫erˈnjɛra/) is Italian for *zipper*.

## Quick start

```rust
use std::{io, pin::pin};

use bytes::Bytes;
use cerniera::{MsDosDateTime, ZipEntry, ZipWriter};
use futures_util::{TryStreamExt, stream};
use tokio::{fs::File, io::AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let modified = MsDosDateTime::new(2026, 3, 10, 12, 30, 0);

    let entries = stream::iter([
        Ok(ZipEntry::File {
            path: "hello.txt".into(),
            modified,
            content: stream::iter([Ok(Bytes::from_static(b"Hello, world!"))]),
        }),
        Ok(ZipEntry::Directory {
            path: "subdir/".into(),
            modified,
        }),
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

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | Yes     | Enables runtime SIMD detection for faster CRC-32. Everything works without it. |
| `jiff`  | No      | Adds `From<jiff::civil::DateTime>` for `MsDosDateTime`. |

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
