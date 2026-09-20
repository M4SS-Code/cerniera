use alloc::{borrow::Cow, string::String, vec::Vec};
use core::fmt;

use bytes::{BufMut, BytesMut};
use crc32fast::Hasher as Crc32Hasher;
use thiserror::Error;

// ── Signatures ────────────────────────────────────────────────────────────────

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_DATA_DESC: u32 = 0x0807_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_ZIP64_EOCD: u32 = 0x0606_4b50;
const SIG_ZIP64_EOCD_LOC: u32 = 0x0706_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;

// ZIP64 extra-field block tag.
const TAG_ZIP64: u16 = 0x0001;

// version needed to extract for entries using ZIP64 (APPNOTE §4.4.3.2)
const VERSION_ZIP64: u16 = 45;
// version made by: Unix (0x03) in the high byte; the low byte is the
// spec version of the software that wrote the entry
const VERSION_MADE_BY_OS: u16 = 3 << 8;
// version made by for records that are not per-entry (the ZIP64 EOCD):
// Unix / spec 4.5
const VERSION_MADE_BY: u16 = VERSION_MADE_BY_OS | VERSION_ZIP64;

// ── Date / time ──────────────────────────────────────────────────────────────

/// Error returned when [`MsDosDateTime::new`] is given an invalid date or time.
#[derive(Debug, Error)]
#[error("invalid MS-DOS date/time")]
#[non_exhaustive]
pub struct InvalidMsDosDateTime;

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
#[derive(Debug, Error)]
#[error("file name length {} exceeds 65535 bytes", path.len())]
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

/// Minimum "version needed to extract" for a compression method
/// (APPNOTE §4.4.3.2). Zstandard (method 93) has no entry in the
/// published table; 4.5 is the oldest version that can reasonably
/// claim to handle it.
const fn method_version_needed(method: CompressionMethod) -> u16 {
    match method {
        CompressionMethod::Stored | CompressionMethod::Deflate => 20,
        CompressionMethod::Bzip2 => 46,
        CompressionMethod::Lzma => 63,
        CompressionMethod::Zstd => 45,
    }
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

/// Whether an entry is a file or a directory; determines the local
/// header's general-purpose flag bits and version.
#[derive(Clone, Copy)]
enum EntryKind {
    /// A file entry: its local header is written before the sizes are
    /// known, so CRC and sizes are deferred to a data descriptor (GP bit
    /// 3) and ZIP64 capability is declared up front.
    File,
    /// A directory entry: zero-length by definition, so its local header
    /// is complete at write time - no data descriptor (APPNOTE 4.4.3.2:
    /// 2.0 - file is a folder).
    Directory,
}

impl EntryKind {
    /// General-purpose flag bits shared by the local and central
    /// directory headers: bit 11 (UTF-8 name) for both kinds, plus bit 3
    /// (data descriptor) for files only.
    fn gp_flag(self) -> u16 {
        match self {
            EntryKind::File => 0x0808,
            EntryKind::Directory => 0x0800,
        }
    }

    /// Version needed for the entry's local header (APPNOTE 4.4.3.1: the
    /// highest applicable feature).
    fn local_version(self, method: CompressionMethod) -> u16 {
        match self {
            EntryKind::File => u16::max(method_version_needed(method), VERSION_ZIP64),
            EntryKind::Directory => 20,
        }
    }

    /// Whether a path names a directory entry (trailing `/`).
    fn for_path(path: &str) -> Self {
        if path.ends_with('/') {
            EntryKind::Directory
        } else {
            EntryKind::File
        }
    }
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
        encode_local_header(path.as_str(), modified, method, EntryKind::File, buf);
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
    /// was not called or the file was already ended), or if the active file
    /// uses a compressed method - use
    /// [`end_file_compressed`](Self::end_file_compressed) for those.
    pub fn end_file(&mut self, buf: &mut BytesMut) {
        // Check the method before taking the entry out: a failed assert
        // (catchable with `catch_unwind`) must leave the entry active
        // rather than lose it from both `active` and the central
        // directory, which finish() would then silently omit.
        if let Some(active) = self.active.as_ref() {
            assert!(
                active.method == CompressionMethod::Stored,
                "end_file() called on a {:?} entry; use end_file_compressed() to finalize compressed entries",
                active.method
            );
        }
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
    /// was not called or the file was already ended), or if the active file
    /// is [`Stored`](CompressionMethod::Stored) - use
    /// [`end_file`](Self::end_file) for those.
    pub fn end_file_compressed(&mut self, compressed_size: u64, buf: &mut BytesMut) {
        // Check the method before taking the entry out: a failed assert
        // (catchable with `catch_unwind`) must leave the entry active
        // rather than lose it from both `active` and the central
        // directory, which finish() would then silently omit.
        if let Some(active) = self.active.as_ref() {
            assert!(
                active.method != CompressionMethod::Stored,
                "end_file_compressed() called on a Stored entry; use end_file() to finalize stored entries"
            );
        }
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

    /// Encode a directory entry (local header) into `buf`.
    ///
    /// A directory is zero-length by definition, so the local header
    /// carries no data descriptor.
    ///
    /// # Panics
    ///
    /// Panics if a previous file was not ended with [`end_file`](Self::end_file)
    /// or [`end_file_compressed`](Self::end_file_compressed).
    pub fn add_directory(&mut self, path: ZipPath, modified: MsDosDateTime, buf: &mut BytesMut) {
        assert!(self.active.is_none(), "previous file not ended");

        let local_offset = self.offset;
        let before = buf.len();
        encode_local_header(
            path.as_str(),
            modified,
            CompressionMethod::Stored,
            EntryKind::Directory,
            buf,
        );
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

    /// Encode the central directory and the end-of-central-directory
    /// trailer into `buf`. This finalizes the archive.
    ///
    /// A ZIP64 end-of-central-directory record and locator are written only
    /// when the standard EOCD's 16/32-bit fields cannot represent the
    /// archive (APPNOTE §4.4.22-4.4.24); otherwise the archive ends with
    /// the plain 22-byte EOCD.
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

        let entries = self.cd.len() as u64;
        // The standard EOCD only has 16/32-bit fields; a ZIP64 EOCD is
        // required once any of them would not fit - or would carry a
        // sentinel value of its own (APPNOTE §4.4.22-4.4.24).
        if requires_zip64_eocd(entries, cd_size, cd_start) {
            let zip64_eocd_offset = self.offset;
            encode_zip64_eocd(entries, cd_size, cd_start, buf);
            encode_zip64_eocd_locator(zip64_eocd_offset, buf);
        }
        encode_eocd(entries, cd_size, cd_start, buf);
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
/// CRC-32 and sizes are all zero: for files GP bit 3 (data descriptor)
/// is set because the header is written before the sizes are known, and
/// for directories the size is known to be zero.
#[expect(
    clippy::cast_possible_truncation,
    reason = "ZipPath guarantees the name fits in u16"
)]
fn encode_local_header(
    path: &str,
    modified: MsDosDateTime,
    method: CompressionMethod,
    kind: EntryKind,
    b: &mut BytesMut,
) {
    let name = path.as_bytes();
    b.reserve(30 + name.len());

    b.put_u32_le(SIG_LOCAL);
    b.put_u16_le(kind.local_version(method));
    b.put_u16_le(kind.gp_flag());
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

/// Central directory file header: 46 bytes fixed + `name.len()`, plus a
/// ZIP64 extra field when a 32-bit size/offset field does not fit.
///
/// The 32-bit fields carry the real values whenever they fit; a field
/// that does not fit - or that would carry the sentinel value itself -
/// is written as a `0xFFFF_FFFF` sentinel and repeated as an 8-byte
/// value in the ZIP64 extra block, whose fields appear in fixed order
/// and only when the corresponding record field is a sentinel (APPNOTE
/// §4.5.3).
#[expect(
    clippy::cast_possible_truncation,
    reason = "ZipPath guarantees the name fits in u16"
)]
fn encode_cd_entry(e: &CdEntry, b: &mut BytesMut) {
    let name = e.path.as_str().as_bytes();
    let kind = EntryKind::for_path(e.path.as_str());
    let external_attr: u32 = match kind {
        EntryKind::Directory => 0o40_755 << 16, // S_IFDIR + rwxr-xr-x
        EntryKind::File => 0o100_644 << 16,     // S_IFREG + rw-r--r--
    };

    // A 32-bit field that cannot hold the value becomes a sentinel and is
    // repeated in the ZIP64 extra block (APPNOTE §4.5.3).
    let compressed = cd_field32(e.compressed_size);
    let uncompressed = cd_field32(e.uncompressed_size);
    let offset = cd_field32(e.local_offset);
    let zip64_fields = u8::from(compressed.is_none())
        + u8::from(uncompressed.is_none())
        + u8::from(offset.is_none());
    let extra_len: u16 = if zip64_fields == 0 {
        0
    } else {
        u16::from(4 + 8 * zip64_fields)
    };

    b.reserve(46 + name.len() + usize::from(extra_len));

    // The central directory is the authoritative header: it declares the
    // highest feature actually used - the method minimum, raised to 4.5
    // when a ZIP64 extra field is present (APPNOTE §4.4.3.1).
    let version = if zip64_fields > 0 {
        u16::max(method_version_needed(e.method), VERSION_ZIP64)
    } else {
        method_version_needed(e.method)
    };

    b.put_u32_le(SIG_CENTRAL);
    // The made-by version never claims less than the entry's
    // version-needed (a 6.3 LZMA entry should not say the writer
    // implements only 4.5) and never less than the 4.5 baseline
    // cerniera itself implements.
    b.put_u16_le(VERSION_MADE_BY_OS | u16::max(version, VERSION_ZIP64));
    b.put_u16_le(version);
    b.put_u16_le(kind.gp_flag());
    b.put_u16_le(e.method as u16);
    b.put_u16_le(e.modified.time);
    b.put_u16_le(e.modified.date);
    b.put_u32_le(e.crc32);
    b.put_u32_le(compressed.unwrap_or(u32::MAX));
    b.put_u32_le(uncompressed.unwrap_or(u32::MAX));
    b.put_u16_le(name.len() as u16);
    b.put_u16_le(extra_len);
    b.put_u16_le(0); // file comment length
    b.put_u16_le(0); // disk number start
    b.put_u16_le(0); // internal file attributes
    b.put_u32_le(external_attr);
    b.put_u32_le(offset.unwrap_or(u32::MAX));
    b.put_slice(name);
    if zip64_fields > 0 {
        // ZIP64 extended information extra field (APPNOTE §4.5.3):
        // fixed field order, present only when the record field is a
        // sentinel.
        b.put_u16_le(TAG_ZIP64);
        b.put_u16_le(u16::from(8 * zip64_fields));
        if uncompressed.is_none() {
            b.put_u64_le(e.uncompressed_size);
        }
        if compressed.is_none() {
            b.put_u64_le(e.compressed_size);
        }
        if offset.is_none() {
            b.put_u64_le(e.local_offset);
        }
    }
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
    b.put_u16_le(VERSION_ZIP64);
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
/// `num_entries`, `cd_size`, and `cd_offset` are written as real values
/// while they fit the 16/32-bit fields; a field that does not fit - or
/// that would carry the sentinel value itself - is written as a
/// `0xFFFF` / `0xFFFF_FFFF` sentinel and must be backed by a
/// ZIP64 EOCD (APPNOTE §4.4.21-4.4.24). The disk-number fields are 0:
/// cerniera writes single-volume archives, and readers consult the ZIP64
/// EOCD based on the count/size/offset sentinels and the locator, not on
/// the disk-number fields.
fn encode_eocd(num_entries: u64, cd_size: u64, cd_offset: u64, b: &mut BytesMut) {
    b.reserve(22);
    b.put_u32_le(SIG_EOCD);
    b.put_u16_le(0); // disk number
    b.put_u16_le(0); // disk where CD starts
    b.put_u16_le(u16::try_from(num_entries).unwrap_or(0xFFFF)); // entries on this disk
    b.put_u16_le(u16::try_from(num_entries).unwrap_or(0xFFFF)); // total entries
    b.put_u32_le(u32::try_from(cd_size).unwrap_or(u32::MAX)); // CD size
    b.put_u32_le(u32::try_from(cd_offset).unwrap_or(u32::MAX)); // CD offset
    b.put_u16_le(0); // ZIP comment length
}

/// Real value for a central directory 32-bit field, or `None` when the
/// field must carry the `0xFFFF_FFFF` sentinel: the value either does not
/// fit in 32 bits or equals the sentinel itself, in which case readers
/// could not tell a real value apart from the ZIP64 marker - current
/// `OpenJDK` rejects an archive whose sentinel-looking field has no ZIP64
/// extra. Go's archive/zip uses the same sentinel-inclusive threshold.
fn cd_field32(v: u64) -> Option<u32> {
    u32::try_from(v).ok().filter(|&v| v != u32::MAX)
}

/// Whether the standard EOCD's 16/32-bit fields cannot represent the
/// archive, so that a ZIP64 EOCD record is required (APPNOTE
/// §4.4.22-4.4.24). Fields equal to the sentinels (0xFFFF entries,
/// `0xFFFF_FFFF` size/offset) also require the record: a real value
/// published there is indistinguishable from the sentinel.
fn requires_zip64_eocd(num_entries: u64, cd_size: u64, cd_offset: u64) -> bool {
    num_entries >= u64::from(u16::MAX)
        || cd_size >= u64::from(u32::MAX)
        || cd_offset >= u64::from(u32::MAX)
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
    //  CD entry      = 46 + name_len (+ ZIP64 extra only on 32-bit overflow)
    //  ZIP64 EOCD    = 56  (only when the plain EOCD fields overflow)
    //  ZIP64 locator = 20  (same)
    //  Standard EOCD = 22

    #[test]
    fn empty_zip_structure() {
        let zip = collect_archive(|archive, out| {
            let mut buf = BytesMut::new();
            archive.finish(&mut buf);
            emit(&mut buf, out);
        });

        // No entries and no field overflows 32 bits → plain 22-byte EOCD,
        // no ZIP64 trailer.
        assert_eq!(zip.len(), 22);
        assert_eq!(u32le(&zip, 0), SIG_EOCD, "std eocd sig");
        assert_eq!(u16le(&zip, 4), 0, "disk number");
        assert_eq!(u16le(&zip, 6), 0, "disk where CD starts");
        assert_eq!(u16le(&zip, 8), 0, "entries on disk");
        assert_eq!(u16le(&zip, 10), 0, "total entries");
        assert_eq!(u32le(&zip, 12), 0, "cd size");
        assert_eq!(u32le(&zip, 16), 0, "cd offset");
        assert_eq!(u16le(&zip, 20), 0, "comment length");
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
        // Streaming entries always declare ZIP64 capability.
        assert_eq!(u16le(&zip, 4), VERSION_ZIP64, "version needed");
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
        // All values fit in 32 bits → real values, no ZIP64 extra.
        let cd = dd + 16;
        assert_eq!(u32le(&zip, cd), SIG_CENTRAL);
        assert_eq!(u16le(&zip, cd + 4), VERSION_MADE_BY);
        // No ZIP64 extra was needed → the method minimum (2.0) stands.
        assert_eq!(
            u16le(&zip, cd + 6),
            method_version_needed(CompressionMethod::Stored),
            "version needed"
        );
        assert_eq!(u32le(&zip, cd + 20), content.len() as u32, "comp size");
        assert_eq!(u32le(&zip, cd + 24), content.len() as u32, "orig size");
        assert_eq!(u32le(&zip, cd + 42), 0, "local offset");
        let cd_name_len = u16le(&zip, cd + 28) as usize;
        let cd_extra_len = u16le(&zip, cd + 30) as usize;
        assert_eq!(cd_name_len, 9);
        assert_eq!(cd_extra_len, 0, "no ZIP64 extra");
        assert_eq!(u32le(&zip, cd + 16), expected_crc, "cd crc32");

        // ── Standard EOCD ─────────────────────────────────────────────────
        // Small archive: the plain EOCD carries the real values and no
        // ZIP64 trailer is present.
        let cd_entry_size = 46 + cd_name_len + cd_extra_len;
        let eocd = cd + cd_entry_size;
        assert_eq!(u32le(&zip, eocd), SIG_EOCD);
        assert_eq!(u16le(&zip, eocd + 10), 1, "total entries");
        assert_eq!(u32le(&zip, eocd + 12), cd_entry_size as u32, "cd size");
        assert_eq!(u32le(&zip, eocd + 16), cd as u32, "cd offset");
        assert_eq!(zip.len(), eocd + 22);
    }

    #[test]
    fn cd_zip64_extra_only_for_overflowing_fields() {
        let name = "big.bin";

        // Only the compressed size overflows → the extra carries just that
        // field; the other 32-bit fields hold real values.
        let mut entry = CdEntry {
            path: name.try_into().unwrap(),
            modified: MsDosDateTime::default(),
            method: CompressionMethod::Stored,
            crc32: 0,
            compressed_size: u64::from(u32::MAX) + 1,
            uncompressed_size: 1234,
            local_offset: 7,
        };
        let mut b = BytesMut::new();
        encode_cd_entry(&entry, &mut b);
        assert_eq!(b.len(), 46 + name.len() + 12);
        assert_eq!(u32le(&b, 20), u32::MAX, "comp size sentinel");
        assert_eq!(u32le(&b, 24), 1234, "orig size real");
        assert_eq!(u32le(&b, 42), 7, "offset real");
        let cex = 46 + name.len();
        assert_eq!(u16le(&b, cex), TAG_ZIP64);
        assert_eq!(u16le(&b, cex + 2), 8, "one 8-byte field");
        assert_eq!(u64le(&b, cex + 4), entry.compressed_size);

        // All three overflow → 8-byte fields in the fixed order:
        // uncompressed, compressed, offset.
        entry.uncompressed_size = u64::from(u32::MAX) + 2;
        entry.local_offset = u64::from(u32::MAX) + 3;
        let mut b = BytesMut::new();
        encode_cd_entry(&entry, &mut b);
        assert_eq!(b.len(), 46 + name.len() + 28);
        assert_eq!(u16le(&b, cex + 2), 24);
        assert_eq!(u64le(&b, cex + 4), entry.uncompressed_size, "orig first");
        assert_eq!(u64le(&b, cex + 12), entry.compressed_size, "comp second");
        assert_eq!(u64le(&b, cex + 20), entry.local_offset, "offset last");

        // Values exactly at the sentinel also go to the extra: a real
        // 0xFFFF_FFFF in the field is indistinguishable from the
        // sentinel, and current OpenJDK rejects the archive when no
        // ZIP64 extra backs it.
        entry.compressed_size = u64::from(u32::MAX);
        entry.uncompressed_size = u64::from(u32::MAX);
        entry.local_offset = 7;
        let mut b = BytesMut::new();
        encode_cd_entry(&entry, &mut b);
        assert_eq!(b.len(), 46 + name.len() + 20);
        assert_eq!(u32le(&b, 20), u32::MAX, "comp size sentinel");
        assert_eq!(u32le(&b, 24), u32::MAX, "orig size sentinel");
        assert_eq!(u32le(&b, 42), 7, "offset real");
        assert_eq!(u16le(&b, cex), TAG_ZIP64);
        assert_eq!(u16le(&b, cex + 2), 16, "two 8-byte fields");
        assert_eq!(u64le(&b, cex + 4), u64::from(u32::MAX), "orig first");
        assert_eq!(u64le(&b, cex + 12), u64::from(u32::MAX), "comp second");

        // Nothing overflows → no extra field at all.
        entry.compressed_size = 1;
        entry.uncompressed_size = 2;
        entry.local_offset = 3;
        let mut b = BytesMut::new();
        encode_cd_entry(&entry, &mut b);
        assert_eq!(b.len(), 46 + name.len());
        assert_eq!(u16le(&b, 30), 0, "no extra field");
    }

    #[test]
    fn version_needed_by_method() {
        // Method minimums (APPNOTE §4.4.3.2).
        assert_eq!(method_version_needed(CompressionMethod::Stored), 20);
        assert_eq!(method_version_needed(CompressionMethod::Deflate), 20);
        assert_eq!(method_version_needed(CompressionMethod::Bzip2), 46);
        assert_eq!(method_version_needed(CompressionMethod::Lzma), 63);
        assert_eq!(method_version_needed(CompressionMethod::Zstd), 45);

        // End to end: a BZIP2 entry raises the local header above the 4.5
        // ZIP64 floor, and the CD matches it when no ZIP64 extra is
        // needed.
        let zip = collect_archive(|archive, out| {
            let mut buf = BytesMut::new();
            archive.start_file(
                "a.bin".try_into().unwrap(),
                MsDosDateTime::default(),
                CompressionMethod::Bzip2,
                &mut buf,
            );
            emit(&mut buf, out);
            archive.file_data(b"payload");
            out.extend_from_slice(b"payload");
            archive.end_file_compressed(7, &mut buf);
            emit(&mut buf, out);
            archive.finish(&mut buf);
            emit(&mut buf, out);
        });
        assert_eq!(u16le(&zip, 4), 46, "local version needed");
        let eocd = zip.len() - 22;
        let cd_offset = u32le(&zip, eocd + 16) as usize;
        assert_eq!(
            u16le(&zip, cd_offset + 4),
            VERSION_MADE_BY_OS | method_version_needed(CompressionMethod::Bzip2),
            "cd made by"
        );
        assert_eq!(u16le(&zip, cd_offset + 6), 46, "cd version needed");
        assert_eq!(u16le(&zip, cd_offset + 30), 0, "no ZIP64 extra");
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

        // Local header: folder version, no data-descriptor bit, and no
        // descriptor after the header - the CD follows immediately.
        assert_eq!(u16le(&zip, 4), 20, "local version needed (folder)");
        assert_eq!(u16le(&zip, 6), 0x0800, "local flags: no data descriptor");
        let name_len = u16le(&zip, 26) as usize;
        let cd = 30 + name_len;

        assert_eq!(u32le(&zip, cd), SIG_CENTRAL, "CD sig");
        assert_eq!(u16le(&zip, cd + 6), 20, "cd version needed (folder)");
        assert_eq!(u16le(&zip, cd + 8), 0x0800, "cd flags: no data descriptor");
        assert_eq!(u32le(&zip, cd + 20), 0, "comp size zero");
        assert_eq!(u32le(&zip, cd + 24), 0, "orig size zero");
        assert_eq!(u16le(&zip, cd + 30), 0, "no ZIP64 extra");
        let ext_attr = u32le(&zip, cd + 38);
        assert_eq!(ext_attr >> 16 & 0o170_000, 0o040_000, "S_IFDIR bit");
    }

    #[test]
    #[should_panic(expected = "end_file() called on a Deflate entry")]
    fn end_file_rejects_compressed_entry() {
        let mut archive = ZipArchive::new();
        let mut buf = BytesMut::new();
        archive.start_file(
            "a.txt".try_into().unwrap(),
            MsDosDateTime::default(),
            CompressionMethod::Deflate,
            &mut buf,
        );
        archive.file_data(b"data");
        archive.end_file(&mut buf);
    }

    #[test]
    #[should_panic(expected = "end_file_compressed() called on a Stored entry")]
    fn end_file_compressed_rejects_stored_entry() {
        let mut archive = ZipArchive::new();
        let mut buf = BytesMut::new();
        archive.start_file(
            "a.txt".try_into().unwrap(),
            MsDosDateTime::default(),
            CompressionMethod::Stored,
            &mut buf,
        );
        archive.file_data(b"data");
        archive.end_file_compressed(4, &mut buf);
    }

    // std-only: swapping the panic hook keeps the caught panic out of the
    // test output, and the panic hook API is not available in no_std.
    #[cfg(feature = "std")]
    #[test]
    fn wrong_finalizer_panic_leaves_the_entry_active() {
        // The method check runs before the entry is taken out, so a
        // caught panic (catch_unwind, a test harness) must leave the
        // entry usable: the right finalizer completes it and finish()
        // still records it in the central directory.
        use std::panic::{self, AssertUnwindSafe};

        let mut archive = ZipArchive::new();
        let mut buf = BytesMut::new();
        archive.start_file(
            "a.txt".try_into().unwrap(),
            MsDosDateTime::default(),
            CompressionMethod::Deflate,
            &mut buf,
        );
        archive.file_data(b"data");

        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            archive.end_file(&mut buf);
        }));
        panic::set_hook(prev_hook);
        assert!(result.is_err(), "end_file() on a Deflate entry must panic");

        archive.end_file_compressed(4, &mut buf);
        archive.finish(&mut buf);

        // The entry reached the central directory: it follows the local
        // header (30 + 5 name bytes) and the 16-byte data descriptor.
        // The data bytes themselves are written by the caller, not by
        // cerniera, so they are not in `buf` here.
        let cd = 30 + 5 + 16;
        assert_eq!(u32le(&buf, cd), SIG_CENTRAL);
        assert_eq!(&buf[cd + 46..cd + 51], b"a.txt");
    }

    #[test]
    fn zip64_eocd_trigger_at_sentinel_values() {
        // Just below the sentinels → the plain EOCD carries real values.
        assert!(!requires_zip64_eocd(
            u64::from(u16::MAX) - 1,
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX) - 1
        ));
        // At the sentinels → the ZIP64 EOCD records back the fields,
        // since a real 0xFFFF / 0xFFFF_FFFF is indistinguishable from
        // the sentinel.
        assert!(requires_zip64_eocd(u64::from(u16::MAX), 0, 0));
        assert!(requires_zip64_eocd(0, u64::from(u32::MAX), 0));
        assert!(requires_zip64_eocd(0, 0, u64::from(u32::MAX)));
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

        // Navigate to the central directory via the standard EOCD's real
        // offset (small archive → no ZIP64 trailer).
        let eocd = zip.len() - 22;
        assert_eq!(u32le(&zip, eocd), SIG_EOCD);
        let cd_offset = u32le(&zip, eocd + 16) as usize;

        // First CD entry: local offset in the 32-bit field (no ZIP64
        // extra, all values fit).
        assert_eq!(
            u32le(&zip, cd_offset + 42),
            0,
            "first entry local offset = 0"
        );

        // Second CD entry
        let name_len_cd_a = u16le(&zip, cd_offset + 28) as usize;
        let extra_len_cd_a = u16le(&zip, cd_offset + 30) as usize;
        let cd_b = cd_offset + 46 + name_len_cd_a + extra_len_cd_a;
        assert_eq!(
            u64::from(u32le(&zip, cd_b + 42)),
            local_b,
            "second entry local offset"
        );
    }
}
