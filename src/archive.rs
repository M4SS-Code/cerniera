use alloc::{borrow::Cow, string::String, vec::Vec};
use core::fmt;

use bytes::{BufMut, BytesMut};
use crc32fast::Hasher as Crc32Hasher;

// ── Signatures ────────────────────────────────────────────────────────────────

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_DATA_DESC: u32 = 0x0807_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
const SIG_ZIP64_EOCD_LOC: u32 = 0x0706_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;

// ZIP64 extra-field block tag.
const TAG_ZIP64: u16 = 0x0001;

// version needed to extract: 4.5 (ZIP64)
const VERSION_NEEDED: u16 = 45;
// version made by: Unix (0x03) / spec 4.5
const VERSION_MADE_BY: u16 = (3 << 8) | 0x2D;

// ── Date / time ──────────────────────────────────────────────────────────────

/// Error returned when [`MsDosDateTime::new`] is given an invalid date or time.
#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidMsDosDateTime;

impl fmt::Display for InvalidMsDosDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid MS-DOS date/time")
    }
}

impl core::error::Error for InvalidMsDosDateTime {}

/// MS-DOS date and time as stored in ZIP file headers.
///
/// The default value is all zeros, which most extractors display as
/// `1980-00-00 00:00:00`.
///
/// Use [`new`](Self::new) to construct a value from calendar components.
#[derive(Clone, Copy, Debug, Default)]
pub struct MsDosDateTime {
    time: u16,
    date: u16,
}

impl MsDosDateTime {
    /// Create from individual calendar components.
    ///
    /// Returns `None` if any field is out of the valid MS-DOS range.
    /// The day is validated against the actual number of days in the given
    /// month and year (including leap years for February).
    ///
    /// * `year` - 1980..=2107
    /// * `month` - 1..=12
    /// * `day` - 1..=days-in-month
    /// * `hour` - 0..=23
    /// * `minute` - 0..=59
    /// * `second` - 0..=59 (truncated to even)
    #[must_use]
    pub const fn new(
        year: u16,
        month: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
    ) -> Option<Self> {
        if year < 1980
            || year > 2107
            || month < 1
            || month > 12
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        Some(Self {
            time: (hour << 11) | (minute << 5) | (second / 2),
            date: ((year - 1980) << 9) | (month << 5) | day,
        })
    }
}

/// Return the number of days in the given month and year.
///
/// Returns `0` for months outside 1..=12.
const fn days_in_month(year: u16, month: u16) -> u16 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && !year.is_multiple_of(100) || year.is_multiple_of(400) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(feature = "jiff")]
impl TryFrom<jiff::civil::DateTime> for MsDosDateTime {
    type Error = InvalidMsDosDateTime;

    fn try_from(dt: jiff::civil::DateTime) -> Result<Self, Self::Error> {
        let year: u16 = dt.year().try_into().map_err(|_| InvalidMsDosDateTime)?;
        let month: u16 = dt.month().try_into().map_err(|_| InvalidMsDosDateTime)?;
        let day: u16 = dt.day().try_into().map_err(|_| InvalidMsDosDateTime)?;
        let hour: u16 = dt.hour().try_into().map_err(|_| InvalidMsDosDateTime)?;
        let minute: u16 = dt.minute().try_into().map_err(|_| InvalidMsDosDateTime)?;
        let second: u16 = dt.second().try_into().map_err(|_| InvalidMsDosDateTime)?;
        Self::new(year, month, day, hour, minute, second).ok_or(InvalidMsDosDateTime)
    }
}

// ── Paths ─────────────────────────────────────────────────────────────────────

/// Error returned when a path does not fit ZIP's 16-bit name length field.
///
/// Returned by [`ZipPath::new`]. The rejected path can be recovered with
/// [`into_inner`](Self::into_inner).
#[derive(Debug)]
pub struct InvalidZipPath {
    path: Cow<'static, str>,
}

impl InvalidZipPath {
    /// Return the rejected path.
    #[must_use]
    pub fn into_inner(self) -> Cow<'static, str> {
        self.path
    }
}

impl fmt::Display for InvalidZipPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file name length {} exceeds 65535 bytes",
            self.path.len()
        )
    }
}

impl core::error::Error for InvalidZipPath {}

/// A ZIP entry path, validated to fit the format's 16-bit name length field.
///
/// Holds a [`Cow`], so paths built from `&'static str` (e.g. string
/// literals) don't allocate:
///
/// ```rust
/// use cerniera::ZipPath;
///
/// // Borrowed - no allocation.
/// let path = ZipPath::new("docs/report.pdf").unwrap();
/// // Owned.
/// let path: ZipPath = String::from("docs/report.pdf").try_into().unwrap();
/// ```
///
/// Paths are stored as-is: cerniera does not normalize separators or reject
/// special components such as `..`; callers zipping untrusted names should
/// sanitize them first.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ZipPath(Cow<'static, str>);

impl ZipPath {
    /// Validate that `path` fits the 16-bit name length field.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidZipPath`] if `path` is longer than 65535 bytes;
    /// the rejected path can be recovered from the error.
    pub fn new(path: impl Into<Cow<'static, str>>) -> Result<Self, InvalidZipPath> {
        let path = path.into();
        if u16::try_from(path.len()).is_ok() {
            Ok(Self(path))
        } else {
            Err(InvalidZipPath { path })
        }
    }

    /// View the path as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extract the inner [`Cow`].
    #[must_use]
    pub fn into_inner(self) -> Cow<'static, str> {
        self.0
    }
}

impl AsRef<str> for ZipPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ZipPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&'static str> for ZipPath {
    type Error = InvalidZipPath;

    fn try_from(path: &'static str) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<String> for ZipPath {
    type Error = InvalidZipPath;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<Cow<'static, str>> for ZipPath {
    type Error = InvalidZipPath;

    fn try_from(path: Cow<'static, str>) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

// ── Compression ──────────────────────────────────────────────────────────────

/// Compression method stored in ZIP file headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum CompressionMethod {
    /// No compression (method 0).
    #[default]
    Stored = 0,
    /// DEFLATE (method 8).
    Deflate = 8,
    /// BZIP2 (method 12).
    Bzip2 = 12,
    /// LZMA (method 14).
    Lzma = 14,
    /// Zstandard (method 93).
    Zstd = 93,
}

// ── Internal bookkeeping ──────────────────────────────────────────────────────

/// Central-directory metadata accumulated as each entry is completed.
struct CdEntry {
    path: ZipPath,
    modified: MsDosDateTime,
    method: CompressionMethod,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    /// Absolute byte offset of the entry's local file header.
    local_offset: u64,
}

/// Tracks the in-flight file entry whose content is being fed.
struct ActiveFile {
    path: ZipPath,
    modified: MsDosDateTime,
    method: CompressionMethod,
    uncompressed_size: u64,
    local_offset: u64,
    crc: Crc32Hasher,
}

// ── ZipArchive ────────────────────────────────────────────────────────────────

/// Low-level, sans-IO ZIP64 archive encoder.
///
/// Encodes ZIP structures into a caller-supplied [`BytesMut`] buffer.
/// This gives you full control over I/O and compression - bring your own
/// DEFLATE, Zstandard, or any other compressor. See the `deflate_zip` and
/// `sendfile_zip` examples in the repository.
///
/// For a higher-level API that handles everything automatically, use
/// [`ZipWriter`](crate::ZipWriter) instead.
///
/// # Lifecycle
///
/// 1. For each **stored** (uncompressed) file: [`start_file`](Self::start_file) →
///    [`file_data`](Self::file_data) → [`end_file`](Self::end_file)
/// 2. For each **compressed** file: [`start_file`](Self::start_file) →
///    [`file_data`](Self::file_data) →
///    [`end_file_compressed`](Self::end_file_compressed)
/// 3. For each directory: [`add_directory`](Self::add_directory)
/// 4. When done: [`finish`](Self::finish)
pub struct ZipArchive {
    cd: Vec<CdEntry>,
    offset: u64,
    active: Option<ActiveFile>,
}

impl ZipArchive {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cd: Vec::new(),
            offset: 0,
            active: None,
        }
    }

    /// Encode a local file header into `buf` and begin tracking the entry.
    ///
    /// For [`Stored`](CompressionMethod::Stored) entries, feed data via
    /// [`file_data`](Self::file_data), then call [`end_file`](Self::end_file).
    ///
    /// For compressed entries (e.g. [`Deflate`](CompressionMethod::Deflate)),
    /// feed the *uncompressed* data via [`file_data`](Self::file_data) (for
    /// CRC + uncompressed size tracking), write the compressed bytes to the
    /// output yourself, then call
    /// [`end_file_compressed`](Self::end_file_compressed) with the compressed
    /// size.
    ///
    /// # Panics
    ///
    /// Panics if a previous file was not ended with [`end_file`](Self::end_file)
    /// or [`end_file_compressed`](Self::end_file_compressed).
    pub fn start_file(
        &mut self,
        path: ZipPath,
        modified: MsDosDateTime,
        method: CompressionMethod,
        buf: &mut BytesMut,
    ) {
        assert!(self.active.is_none(), "previous file not ended");

        let local_offset = self.offset;
        let before = buf.len();
        encode_local_header(path.as_str(), modified, method, buf);
        self.offset += (buf.len() - before) as u64;

        self.active = Some(ActiveFile {
            path,
            modified,
            method,
            uncompressed_size: 0,
            local_offset,
            crc: Crc32Hasher::new(),
        });
    }

    /// Feed a chunk of **uncompressed** file data for CRC-32 computation.
    ///
    /// For [`Stored`](CompressionMethod::Stored) entries this also advances
    /// the archive offset (since the raw bytes are written to the output).
    ///
    /// The caller is responsible for forwarding the actual bytes to the
    /// output; this method only updates internal bookkeeping.
    ///
    /// # Panics
    ///
    /// Panics if no file is currently active (i.e. [`start_file`](Self::start_file)
    /// was not called or the file was already ended).
    pub fn file_data(&mut self, data: &[u8]) {
        let active = self.active.as_mut().expect("no active file");
        active.crc.update(data);
        active.uncompressed_size += data.len() as u64;
        if active.method == CompressionMethod::Stored {
            self.offset += data.len() as u64;
        }
    }

    /// Finalize a [`Stored`](CompressionMethod::Stored) file entry.
    ///
    /// Uses the internally computed CRC-32 and sets compressed size equal to
    /// the uncompressed size.
    ///
    /// # Panics
    ///
    /// Panics if no file is currently active (i.e. [`start_file`](Self::start_file)
    /// was not called or the file was already ended).
    pub fn end_file(&mut self, buf: &mut BytesMut) {
        let active = self.active.take().expect("no active file");
        let crc32 = active.crc.finalize();
        let size = active.uncompressed_size;

        let before = buf.len();
        encode_data_descriptor(crc32, size, size, buf);
        self.offset += (buf.len() - before) as u64;

        self.cd.push(CdEntry {
            path: active.path,
            modified: active.modified,
            method: active.method,
            crc32,
            compressed_size: size,
            uncompressed_size: size,
            local_offset: active.local_offset,
        });
    }

    /// Finalize a compressed file entry.
    ///
    /// Uses the internally computed CRC-32 (from uncompressed data fed via
    /// [`file_data`](Self::file_data)). The caller provides `compressed_size`
    /// - the number of compressed bytes actually written to the output.
    ///
    /// # Panics
    ///
    /// Panics if no file is currently active (i.e. [`start_file`](Self::start_file)
    /// was not called or the file was already ended).
    pub fn end_file_compressed(&mut self, compressed_size: u64, buf: &mut BytesMut) {
        let active = self.active.take().expect("no active file");
        let crc32 = active.crc.finalize();

        self.offset += compressed_size;
        let before = buf.len();
        encode_data_descriptor(crc32, compressed_size, active.uncompressed_size, buf);
        self.offset += (buf.len() - before) as u64;

        self.cd.push(CdEntry {
            path: active.path,
            modified: active.modified,
            method: active.method,
            crc32,
            compressed_size,
            uncompressed_size: active.uncompressed_size,
            local_offset: active.local_offset,
        });
    }

    /// Encode a directory entry (local header + data descriptor) into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if a previous file was not ended with [`end_file`](Self::end_file)
    /// or [`end_file_compressed`](Self::end_file_compressed).
    pub fn add_directory(&mut self, path: ZipPath, modified: MsDosDateTime, buf: &mut BytesMut) {
        assert!(self.active.is_none(), "previous file not ended");

        let local_offset = self.offset;
        let before = buf.len();
        encode_local_header(path.as_str(), modified, CompressionMethod::Stored, buf);
        encode_data_descriptor(0, 0, 0, buf);
        self.offset += (buf.len() - before) as u64;

        self.cd.push(CdEntry {
            path,
            modified,
            method: CompressionMethod::Stored,
            crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            local_offset,
        });
    }

    /// Encode the central directory, ZIP64 EOCD, locator, and standard EOCD
    /// into `buf`. This finalizes the archive.
    ///
    /// # Panics
    ///
    /// Panics if a previous file was not ended with [`end_file`](Self::end_file)
    /// or [`end_file_compressed`](Self::end_file_compressed).
    pub fn finish(&mut self, buf: &mut BytesMut) {
        assert!(self.active.is_none(), "file not ended before finish");

        let cd_start = self.offset;

        let before = buf.len();
        for e in &self.cd {
            encode_cd_entry(e, buf);
        }
        let cd_size = (buf.len() - before) as u64;
        self.offset += cd_size;

        let zip64_eocd_offset = self.offset;
        encode_zip64_eocd(self.cd.len() as u64, cd_size, cd_start, buf);
        encode_zip64_eocd_locator(zip64_eocd_offset, buf);
        encode_eocd(buf);
    }
}

impl Default for ZipArchive {
    fn default() -> Self {
        Self::new()
    }
}

// ── ZIP format encoding ───────────────────────────────────────────────────────

/// Local file header: 30 bytes fixed + `name.len()`.
///
/// CRC-32 and sizes are all zero because GP bit 3 (data descriptor) is set.
/// The real values appear in the data descriptor that follows the file
/// data, and in the central directory's ZIP64 extra field.
#[expect(
    clippy::cast_possible_truncation,
    reason = "ZipPath guarantees the name fits in u16"
)]
fn encode_local_header(
    path: &str,
    modified: MsDosDateTime,
    method: CompressionMethod,
    b: &mut BytesMut,
) {
    let name = path.as_bytes();
    b.reserve(30 + name.len());

    b.put_u32_le(SIG_LOCAL);
    b.put_u16_le(VERSION_NEEDED);
    b.put_u16_le(0x0808); // GP flag: bit 3 = data descriptor, bit 11 = UTF-8
    b.put_u16_le(method as u16);
    b.put_u16_le(modified.time);
    b.put_u16_le(modified.date);
    b.put_u32_le(0); // CRC-32          ─┐ all deferred to
    b.put_u32_le(0); // compressed size  │ the ZIP64 data
    b.put_u32_le(0); // original size   ─┘ descriptor
    b.put_u16_le(name.len() as u16);
    b.put_u16_le(0); // extra field length
    b.put_slice(name);
}

/// Data descriptor: 16 bytes, or 24 bytes for entries of 4 GiB or larger.
///
/// `sig(4) + crc32(4) + compressed_size(4|8) + uncompressed_size(4|8)`
///
/// The local header carries no ZIP64 extra field, so readers expect the
/// classic 4-byte sizes (APPNOTE 4.5.3); extractors that do handle 8-byte
/// descriptors detect them from the actual data size. Use 4-byte sizes
/// whenever they fit and the ZIP64 form only when a size needs 8 bytes.
fn encode_data_descriptor(
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    b: &mut BytesMut,
) {
    b.reserve(24);
    b.put_u32_le(SIG_DATA_DESC);
    b.put_u32_le(crc32);
    if let (Ok(compressed), Ok(uncompressed)) = (
        u32::try_from(compressed_size),
        u32::try_from(uncompressed_size),
    ) {
        b.put_u32_le(compressed);
        b.put_u32_le(uncompressed);
    } else {
        b.put_u64_le(compressed_size);
        b.put_u64_le(uncompressed_size);
    }
}

/// Central directory file header: 46 bytes fixed + `name.len()` + 28 bytes ZIP64 extra.
///
/// The 32-bit size and offset fields carry `0xFFFF_FFFF` sentinels; the real
/// 64-bit values live in the ZIP64 extra block per APPNOTE §4.5.3.
// ZIP64 extra: tag(2) + block_len(2) + orig(8) + comp(8) + local_offset(8) = 28
const CD_EXTRA_LEN: u16 = 28;

#[expect(
    clippy::cast_possible_truncation,
    reason = "ZipPath guarantees the name fits in u16"
)]
fn encode_cd_entry(e: &CdEntry, b: &mut BytesMut) {
    let name = e.path.as_str().as_bytes();
    let external_attr: u32 = if e.path.as_str().ends_with('/') {
        0o40_755 << 16 // S_IFDIR + rwxr-xr-x
    } else {
        0o100_644 << 16 // S_IFREG + rw-r--r--
    };
    b.reserve(46 + name.len() + CD_EXTRA_LEN as usize);

    b.put_u32_le(SIG_CENTRAL);
    b.put_u16_le(VERSION_MADE_BY);
    b.put_u16_le(VERSION_NEEDED);
    b.put_u16_le(0x0808); // GP flag: bit 3 = data descriptor, bit 11 = UTF-8
    b.put_u16_le(e.method as u16);
    b.put_u16_le(e.modified.time);
    b.put_u16_le(e.modified.date);
    b.put_u32_le(e.crc32);
    b.put_u32_le(0xFFFF_FFFF); // compressed size  ─┐ sentinel:
    b.put_u32_le(0xFFFF_FFFF); // uncompressed size  │ see ZIP64 extra
    b.put_u16_le(name.len() as u16);
    b.put_u16_le(CD_EXTRA_LEN);
    b.put_u16_le(0); // file comment length
    b.put_u16_le(0); // disk number start
    b.put_u16_le(0); // internal file attributes
    b.put_u32_le(external_attr);
    b.put_u32_le(0xFFFF_FFFF); // local header offset ── sentinel
    b.put_slice(name);
    // ZIP64 extended information extra field
    b.put_u16_le(TAG_ZIP64);
    b.put_u16_le(24); // block payload length
    b.put_u64_le(e.uncompressed_size);
    b.put_u64_le(e.compressed_size);
    b.put_u64_le(e.local_offset);
}

/// ZIP64 end-of-central-directory record (56 bytes, no extensible data sector).
///
/// Layout: `sig(4) + record_size(8) + vmb(2) + vne(2) + disk(4) + cd_disk(4)
///          + entries_disk(8) + entries_total(8) + cd_size(8) + cd_offset(8)`
fn encode_zip64_eocd(num_entries: u64, cd_size: u64, cd_offset: u64, b: &mut BytesMut) {
    b.reserve(56);
    b.put_u32_le(SIG_ZIP64_EOCD);
    b.put_u64_le(44); // size of the remaining record (56 - 12)
    b.put_u16_le(VERSION_MADE_BY);
    b.put_u16_le(VERSION_NEEDED);
    b.put_u32_le(0); // number of this disk
    b.put_u32_le(0); // disk where CD starts
    b.put_u64_le(num_entries); // CD entries on this disk
    b.put_u64_le(num_entries); // total CD entries
    b.put_u64_le(cd_size);
    b.put_u64_le(cd_offset);
}

/// ZIP64 EOCD locator (20 bytes).
///
/// Points back to the ZIP64 EOCD record so extractors can find it without
/// scanning backwards from the standard EOCD.
fn encode_zip64_eocd_locator(zip64_eocd_offset: u64, b: &mut BytesMut) {
    b.reserve(20);
    b.put_u32_le(SIG_ZIP64_EOCD_LOC);
    b.put_u32_le(0); // disk containing ZIP64 EOCD
    b.put_u64_le(zip64_eocd_offset);
    b.put_u32_le(1); // total number of disks
}

/// Standard EOCD (22 bytes).
///
/// All fields carry sentinel values so that extractors are forced to use
/// the ZIP64 EOCD instead.
fn encode_eocd(b: &mut BytesMut) {
    b.reserve(22);
    b.put_u32_le(SIG_EOCD);
    b.put_u16_le(0xFFFF); // disk number            ─┐
    b.put_u16_le(0xFFFF); // disk where CD starts    │
    b.put_u16_le(0xFFFF); // entries on this disk     │ all sentinels:
    b.put_u16_le(0xFFFF); // total entries            │ see ZIP64 EOCD
    b.put_u32_le(0xFFFF_FFFF); // CD size             │
    b.put_u32_le(0xFFFF_FFFF); // CD offset          ─┘
    b.put_u16_le(0); // ZIP comment length
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[expect(clippy::cast_possible_truncation, reason = "test data is small")]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn u16le(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
    }
    fn u32le(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn u64le(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// Collect all output from a `ZipArchive` into a flat byte vec.
    /// Each method that writes to buf gets its output appended.
    fn collect_archive(f: impl FnOnce(&mut ZipArchive, &mut Vec<u8>)) -> Vec<u8> {
        let mut archive = ZipArchive::new();
        let mut out = Vec::new();
        f(&mut archive, &mut out);
        out
    }

    fn emit(buf: &mut BytesMut, out: &mut Vec<u8>) {
        out.extend_from_slice(buf);
        buf.clear();
    }

    // ── Layout constants ──────────────────────────────────────────────────────
    //
    //  Local header  = 30 + name_len        (no extra field)
    //  Data descr.   = 16                  (sig+crc+comp_size+orig_size; 24 if ≥ 4 GiB)
    //  CD entry      = 46 + name_len + 28  (ZIP64 extra: tag+len+orig+comp+off)
    //  ZIP64 EOCD    = 56
    //  ZIP64 locator = 20
    //  Standard EOCD = 22

    #[test]
    fn empty_zip_structure() {
        let zip = collect_archive(|archive, out| {
            let mut buf = BytesMut::new();
            archive.finish(&mut buf);
            emit(&mut buf, out);
        });

        // No entries → offset stays at 0. Trailer = 56 + 20 + 22 = 98 bytes.
        assert_eq!(zip.len(), 98);

        // ZIP64 EOCD at byte 0
        assert_eq!(u32le(&zip, 0), SIG_ZIP64_EOCD, "zip64 eocd sig");
        assert_eq!(u64le(&zip, 24), 0u64, "entries on disk");
        assert_eq!(u64le(&zip, 32), 0u64, "total entries");
        assert_eq!(u64le(&zip, 40), 0u64, "cd size");
        assert_eq!(u64le(&zip, 48), 0u64, "cd offset");

        // ZIP64 EOCD locator at byte 56
        assert_eq!(u32le(&zip, 56), SIG_ZIP64_EOCD_LOC, "locator sig");
        assert_eq!(u64le(&zip, 56 + 8), 0u64, "zip64 eocd at offset 0");

        // Standard EOCD at byte 76
        assert_eq!(u32le(&zip, 76), SIG_EOCD, "std eocd sig");
        assert_eq!(zip.len(), 98);
    }

    #[test]
    fn single_file_structure() {
        let content = b"hello, zip!"; // 11 bytes
        let name = "hello.txt"; //  9 bytes

        let zip = collect_archive(|archive, out| {
            let mut buf = BytesMut::new();

            archive.start_file(
                name.try_into().unwrap(),
                MsDosDateTime::default(),
                CompressionMethod::Stored,
                &mut buf,
            );
            emit(&mut buf, out);

            // Feed content in chunks (like the stream would)
            for chunk in content.chunks(8) {
                archive.file_data(chunk);
                out.extend_from_slice(chunk);
            }

            archive.end_file(&mut buf);
            emit(&mut buf, out);

            archive.finish(&mut buf);
            emit(&mut buf, out);
        });

        // ── Local header ─────────────────────────────────────────────────
        assert_eq!(u32le(&zip, 0), SIG_LOCAL, "local sig");
        assert_eq!(u16le(&zip, 4), VERSION_NEEDED, "version needed");
        assert_eq!(u16le(&zip, 6), 0x0808, "GP bit 3 + bit 11");
        assert_eq!(u32le(&zip, 14), 0, "crc deferred");
        assert_eq!(u32le(&zip, 18), 0, "comp size deferred");
        assert_eq!(u32le(&zip, 22), 0, "orig size deferred");
        let name_len = u16le(&zip, 26) as usize;
        assert_eq!(name_len, 9);
        let extra_len = u16le(&zip, 28) as usize;
        assert_eq!(extra_len, 0);
        assert_eq!(&zip[30..30 + name_len], name.as_bytes());

        // ── Data descriptor ──────────────────────────────────────────────
        let dd = 30 + name_len + content.len();
        assert_eq!(u32le(&zip, dd), SIG_DATA_DESC);
        let expected_crc = {
            let mut h = Crc32Hasher::new();
            h.update(content);
            h.finalize()
        };
        assert_eq!(u32le(&zip, dd + 4), expected_crc, "crc32");
        assert_eq!(u32le(&zip, dd + 8), content.len() as u32, "comp size");
        assert_eq!(u32le(&zip, dd + 12), content.len() as u32, "orig size");

        // ── Central directory ─────────────────────────────────────────────
        let cd = dd + 16;
        assert_eq!(u32le(&zip, cd), SIG_CENTRAL);
        assert_eq!(u16le(&zip, cd + 4), VERSION_MADE_BY);
        assert_eq!(u32le(&zip, cd + 20), 0xFFFF_FFFF, "comp size sentinel");
        assert_eq!(u32le(&zip, cd + 24), 0xFFFF_FFFF, "orig size sentinel");
        assert_eq!(u32le(&zip, cd + 42), 0xFFFF_FFFF, "offset sentinel");
        let cd_name_len = u16le(&zip, cd + 28) as usize;
        let cd_extra_len = u16le(&zip, cd + 30) as usize;
        assert_eq!(cd_name_len, 9);
        assert_eq!(cd_extra_len, 28);
        assert_eq!(u32le(&zip, cd + 16), expected_crc, "cd crc32");
        // ZIP64 extra in CD
        let cex = cd + 46 + cd_name_len;
        assert_eq!(u16le(&zip, cex), TAG_ZIP64);
        assert_eq!(u16le(&zip, cex + 2), 24);
        assert_eq!(u64le(&zip, cex + 4), content.len() as u64, "cd orig size64");
        assert_eq!(
            u64le(&zip, cex + 12),
            content.len() as u64,
            "cd comp size64"
        );
        assert_eq!(u64le(&zip, cex + 20), 0u64, "local offset = 0");

        // ── ZIP64 EOCD ────────────────────────────────────────────────────
        let cd_entry_size = 46 + cd_name_len + cd_extra_len;
        let z64 = cd + cd_entry_size;
        assert_eq!(u32le(&zip, z64), SIG_ZIP64_EOCD);
        assert_eq!(u64le(&zip, z64 + 24), 1u64, "one entry");
        assert_eq!(u64le(&zip, z64 + 40), cd_entry_size as u64, "cd size");
        assert_eq!(u64le(&zip, z64 + 48), cd as u64, "cd offset");

        // ── ZIP64 locator ─────────────────────────────────────────────────
        let loc = z64 + 56;
        assert_eq!(u32le(&zip, loc), SIG_ZIP64_EOCD_LOC);
        assert_eq!(u64le(&zip, loc + 8), z64 as u64, "zip64 eocd offset");

        // ── Standard EOCD ─────────────────────────────────────────────────
        let eocd = loc + 20;
        assert_eq!(u32le(&zip, eocd), SIG_EOCD);
        assert_eq!(zip.len(), eocd + 22);
    }

    #[test]
    fn directory_entry() {
        let path = "subdir/"; // 7 bytes

        let zip = collect_archive(|archive, out| {
            let mut buf = BytesMut::new();
            archive.add_directory(path.try_into().unwrap(), MsDosDateTime::default(), &mut buf);
            emit(&mut buf, out);
            archive.finish(&mut buf);
            emit(&mut buf, out);
        });

        let name_len = u16le(&zip, 26) as usize;
        // local header + 0 payload + 16-byte descriptor
        let cd = 30 + name_len + 16;

        assert_eq!(u32le(&zip, cd), SIG_CENTRAL, "CD sig");
        let ext_attr = u32le(&zip, cd + 38);
        assert_eq!(ext_attr >> 16 & 0o170_000, 0o040_000, "S_IFDIR bit");
    }

    #[test]
    fn data_descriptor_widths() {
        // Classic 16-byte form when both sizes fit in 32 bits.
        let mut b = BytesMut::new();
        encode_data_descriptor(0xDEAD_BEEF, 1234, 5678, &mut b);
        assert_eq!(b.len(), 16);
        assert_eq!(u32le(&b, 0), SIG_DATA_DESC);
        assert_eq!(u32le(&b, 4), 0xDEAD_BEEF);
        assert_eq!(u32le(&b, 8), 1234);
        assert_eq!(u32le(&b, 12), 5678);

        // The largest sizes still representable in 4 bytes stay classic.
        let max32 = u64::from(u32::MAX);
        let mut b = BytesMut::new();
        encode_data_descriptor(1, max32, max32, &mut b);
        assert_eq!(b.len(), 16);

        // ZIP64 24-byte form once either size needs 8 bytes.
        let mut b = BytesMut::new();
        encode_data_descriptor(1, max32 + 1, 42, &mut b);
        assert_eq!(b.len(), 24);
        assert_eq!(u64le(&b, 8), max32 + 1);
        assert_eq!(u64le(&b, 16), 42);
    }

    #[test]
    fn zip_path_length_validation() {
        // Exactly the u16 limit is accepted.
        assert!(ZipPath::new("a".repeat(65_535)).is_ok());

        // One byte over is rejected and the path can be recovered.
        let long = "a".repeat(65_536);
        let err = ZipPath::new(long.clone()).unwrap_err();
        assert_eq!(err.into_inner(), long);

        // Static strings are stored borrowed - no allocation.
        let path = ZipPath::new("hello.txt").unwrap();
        assert!(matches!(path.into_inner(), Cow::Borrowed("hello.txt")));
    }

    #[test]
    fn ms_dos_date_time_validation() {
        // Extremes of every valid range are accepted.
        assert!(MsDosDateTime::new(1980, 1, 1, 0, 0, 0).is_some());
        assert!(MsDosDateTime::new(2107, 12, 31, 23, 59, 59).is_some());

        // Each component out of range is rejected.
        assert!(MsDosDateTime::new(1979, 12, 31, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2108, 1, 1, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 0, 1, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 13, 1, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 1, 0, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 4, 31, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 1, 1, 24, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 1, 1, 99, 0, 0).is_none());
        assert!(MsDosDateTime::new(2020, 1, 1, 0, 60, 0).is_none());
        assert!(MsDosDateTime::new(2020, 1, 1, 0, 0, 60).is_none());

        // Leap year handling for February.
        assert!(MsDosDateTime::new(2024, 2, 29, 0, 0, 0).is_some());
        assert!(MsDosDateTime::new(2026, 2, 29, 0, 0, 0).is_none());
        assert!(MsDosDateTime::new(2000, 2, 29, 0, 0, 0).is_some());
        assert!(MsDosDateTime::new(2100, 2, 29, 0, 0, 0).is_none());
    }

    #[test]
    fn multiple_entries_offsets() {
        let a_data = b"aaaa";
        let b_data = b"bbbbbbbb";

        let zip = collect_archive(|archive, out| {
            let mut buf = BytesMut::new();

            archive.start_file(
                "a.txt".try_into().unwrap(),
                MsDosDateTime::default(),
                CompressionMethod::Stored,
                &mut buf,
            );
            emit(&mut buf, out);
            archive.file_data(a_data);
            out.extend_from_slice(a_data);
            archive.end_file(&mut buf);
            emit(&mut buf, out);

            archive.start_file(
                "b.txt".try_into().unwrap(),
                MsDosDateTime::default(),
                CompressionMethod::Stored,
                &mut buf,
            );
            emit(&mut buf, out);
            archive.file_data(b_data);
            out.extend_from_slice(b_data);
            archive.end_file(&mut buf);
            emit(&mut buf, out);

            archive.finish(&mut buf);
            emit(&mut buf, out);
        });

        // Compute expected start of second local header.
        let name_len_a = u16le(&zip, 26) as usize; // 5 for "a.txt"
        let local_b = (30 + name_len_a + 4 + 16) as u64;
        assert_eq!(u32le(&zip, local_b as usize), SIG_LOCAL, "second local sig");

        // Navigate to ZIP64 EOCD via the locator embedded in the standard EOCD tail.
        let eocd_std = zip.len() - 22;
        let loc_off = eocd_std - 20;
        let z64_off = u64le(&zip, loc_off + 8) as usize;
        let cd_offset = u64le(&zip, z64_off + 48) as usize;

        // First CD entry: local_offset64 = 0
        let name_len_cd_a = u16le(&zip, cd_offset + 28) as usize;
        let extra_len_cd_a = u16le(&zip, cd_offset + 30) as usize;
        let cex_a = cd_offset + 46 + name_len_cd_a;
        assert_eq!(u64le(&zip, cex_a + 20), 0, "first entry local offset = 0");

        // Second CD entry
        let cd_b = cd_offset + 46 + name_len_cd_a + extra_len_cd_a;
        let cex_b = cd_b + 46 + u16le(&zip, cd_b + 28) as usize;
        assert_eq!(
            u64le(&zip, cex_b + 20),
            local_b,
            "second entry local offset"
        );
    }
}
