//! The events an eBPF program emits, and how they are decoded.
//!
//! The macros of `xbpf.h` write a `struct bpf_tracing_event` into the
//! `bpf_tracing_events` ring buffer, and [`crate::tracing`] reads the records
//! back out. This module holds the user space half of that wire format: an
//! [`Event`] is decoded from the raw bytes of one record.
//!
//! A record is laid out as the eBPF side writes it, in native endianness:
//!
//! | offset | size  | field                                     |
//! |--------|-------|-------------------------------------------|
//! | 0      | 1     | level, see [`Kind`]                       |
//! | 1      | 1     | kind, see [`Kind`]                        |
//! | 2      | 2     | id of the CPU that emitted the event      |
//! | 4      | 128   | NUL-padded message                        |
//! | 132    | 128   | NUL-padded file name, source location only |
//! | 260    | 4     | line number, source location only         |
//!
//! The last two fields are only present if the eBPF program was compiled with
//! `BPF_TRACING_SOURCE_LOC`, which the `tracing-source-loc` feature sets. They
//! are decoded whenever the record is long enough to hold them, so a program
//! compiled with source locations can be read by a user space program that was
//! not, but not the other way around.

use crate::map::FromRecord;
use std::{error::Error, fmt};

use tracing::Level;

// TODO: this currently has two definitions. Make sure there's only one.
/// The length of the strings a record carries, mirroring `BPF_TRACING_STR_LEN`.
const BPF_TRACING_STR_LEN: usize = 128;

/// The size of a record without a source location.
const EVENT_BASE_SIZE: usize = 4 + BPF_TRACING_STR_LEN;

/// The size of a record that carries the file and line it was emitted from.
const EVENT_WITH_FILE_SIZE: usize = EVENT_BASE_SIZE + BPF_TRACING_STR_LEN + 4;

/// The reason a record could not be decoded into an [`Event`].
///
/// Every variant means the record doesn't match the layout described in the
/// [module documentation](self), which usually points at an eBPF program built
/// against a different `xbpf.h` than the user space program was built against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventDecodeError {
    /// The record is shorter than the layout requires.
    BufferTooShort {
        /// The number of bytes the layout requires.
        expected: usize,
        /// The number of bytes the record actually holds.
        actual: usize,
    },
    /// The level byte is not one of the five levels of [`Level`].
    InvalidLevel(u8),
    /// The kind byte is not one of the three kinds of [`Kind`].
    InvalidKind(u8),
    /// The named string field is not valid UTF-8.
    InvalidUtf8(&'static str),
}

impl fmt::Display for EventDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventDecodeError::BufferTooShort { expected, actual } => write!(
                f,
                "event buffer too short (expected at least {expected} bytes, got {actual})",
            ),
            EventDecodeError::InvalidLevel(level) => {
                write!(f, "invalid log level: {level}")
            }
            EventDecodeError::InvalidKind(kind) => write!(f, "invalid event kind: {kind}"),
            EventDecodeError::InvalidUtf8(field) => {
                write!(f, "invalid UTF-8 in {field} field")
            }
        }
    }
}

impl Error for EventDecodeError {}

/// What an [`Event`] does to the trace it belongs to.
///
/// The eBPF side picks the kind through the macro that emits the event:
/// `bpf_info` and friends emit a [`Kind::Message`], `bpf_start_info_span` and
/// friends a [`Kind::StartSpan`], and `bpf_end_span` a [`Kind::EndSpan`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A single event at the given level.
    Message(Level),
    /// The start of a span at the given level. Everything emitted on the same
    /// CPU until the matching [`Kind::EndSpan`] is nested inside it.
    StartSpan(Level),
    /// The end of the innermost span on the CPU whose name matches the content
    /// of the event. Ending a span that was never started is ignored.
    EndSpan,
}

/// A single decoded record from the `bpf_tracing_events` ring buffer.
///
/// # Examples
///
/// Decoding a record that carries a source location:
///
/// ```
/// use tracing::Level;
/// use xbpf::event::{Event, Kind};
///
/// let mut buf = vec![0u8; 264];
/// buf[0] = 3; // INFO
/// buf[1] = 0; // a message rather than a span
/// buf[2..4].copy_from_slice(&2u16.to_ne_bytes());
/// buf[4..9].copy_from_slice(b"hello");
/// buf[132..142].copy_from_slice(b"prog.bpf.c");
/// buf[260..264].copy_from_slice(&42u32.to_ne_bytes());
///
/// let event = Event::try_from(buf.as_slice()).unwrap();
/// assert_eq!(event.kind, Kind::Message(Level::INFO));
/// assert_eq!(event.content, "hello");
/// assert_eq!(event.cpu, 2);
/// assert_eq!(event.file.as_deref(), Some("prog.bpf.c"));
/// assert_eq!(event.line, Some(42));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Event {
    /// Whether the event is a message, or opens or closes a span.
    pub kind: Kind,

    /// The formatted message, or the name of the span for [`Kind::StartSpan`]
    /// and [`Kind::EndSpan`].
    pub content: String,

    /// The id of the CPU the event was emitted on. Spans are tracked per CPU,
    /// since an eBPF program can run on every CPU concurrently.
    pub cpu: usize,

    /// The eBPF source file the event was emitted from, if the program was
    /// compiled with source locations and the name is not empty.
    pub file: Option<String>,

    /// The line the event was emitted from, if the program was compiled with
    /// source locations.
    pub line: Option<u32>,
}

impl TryFrom<&[u8]> for Event {
    type Error = EventDecodeError;

    /// Decodes one record of the ring buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EventDecodeError`] if `buf` is shorter than a record, or if
    /// one of its fields holds a value the layout doesn't allow.
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < EVENT_BASE_SIZE {
            return Err(EventDecodeError::BufferTooShort {
                expected: EVENT_BASE_SIZE,
                actual: buf.len(),
            });
        }

        let level_raw = buf[0];
        let kind_raw = buf[1];
        let cpu = u16::from_ne_bytes([buf[2], buf[3]]) as usize;

        let msg_start = 4;
        let msg_end = msg_start + BPF_TRACING_STR_LEN;
        let msg = parse_cstr(&buf[msg_start..msg_end], "msg")?;

        let has_file = buf.len() >= EVENT_WITH_FILE_SIZE;
        if cfg!(feature = "tracing-source-loc") && !has_file {
            return Err(EventDecodeError::BufferTooShort {
                expected: EVENT_WITH_FILE_SIZE,
                actual: buf.len(),
            });
        }

        let (file, line) = if has_file {
            let file_start = msg_end;
            let file_end = file_start + BPF_TRACING_STR_LEN;
            let file = parse_cstr(&buf[file_start..file_end], "file")?;

            let line_start = file_end;
            let line_bytes: [u8; 4] = buf[line_start..line_start + 4]
                .try_into()
                .expect("line bytes length verified");
            let line = u32::from_ne_bytes(line_bytes);

            let file = if file.is_empty() { None } else { Some(file) };
            (file, Some(line))
        } else {
            (None, None)
        };

        let kind = match kind_raw {
            0 => Kind::Message(parse_level(level_raw)?),
            1 => Kind::StartSpan(parse_level(level_raw)?),
            2 => Kind::EndSpan,
            other => return Err(EventDecodeError::InvalidKind(other)),
        };

        Ok(Event {
            kind,
            content: msg,
            cpu,
            file,
            line,
        })
    }
}

impl FromRecord for Event {
    type Error = EventDecodeError;

    fn from_record(record: &[u8]) -> Result<Self, Self::Error> {
        Event::try_from(record)
    }
}

/// Converts the level byte of a record into a [`Level`], keeping the order the
/// `BPF_TRACING_LEVEL_*` constants define.
fn parse_level(level: u8) -> Result<Level, EventDecodeError> {
    match level {
        1 => Ok(Level::ERROR),
        2 => Ok(Level::WARN),
        3 => Ok(Level::INFO),
        4 => Ok(Level::DEBUG),
        5 => Ok(Level::TRACE),
        other => Err(EventDecodeError::InvalidLevel(other)),
    }
}

/// Reads a NUL-padded string field, naming it `field` in the error.
///
/// The eBPF side writes into a fixed size array, so the string runs up to the
/// first NUL byte, or to the end of the field if it filled it completely.
fn parse_cstr(bytes: &[u8], field: &'static str) -> Result<String, EventDecodeError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end])
        .map(|s| s.to_string())
        .map_err(|_| EventDecodeError::InvalidUtf8(field))
}

/// What distinguishes one [`tracing`] callsite from another.
///
/// [`tracing`] expects a callsite to be a fixed point in the source, with
/// metadata that lives for `'static`. Events from eBPF have no such thing, so
/// [`crate::tracing`] synthesizes one callsite per distinct key and reuses it.
/// The key holds everything the metadata is built from: the file and line the
/// event came from, whether it opens a span, and its level.
pub type CallsiteKey = (Option<String>, Option<u32>, bool, tracing::metadata::Level);

impl TryFrom<Event> for CallsiteKey {
    type Error = ();

    /// Returns the callsite the event belongs to.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` for [`Kind::EndSpan`], which closes a span that is
    /// already open and therefore has no callsite of its own.
    fn try_from(event: Event) -> Result<Self, Self::Error> {
        match event.kind {
            Kind::StartSpan(level) => Ok((event.file.clone(), event.line, true, level)),
            Kind::EndSpan => Err(()),
            Kind::Message(level) => Ok((event.file.clone(), event.line, false, level)),
        }
    }
}
