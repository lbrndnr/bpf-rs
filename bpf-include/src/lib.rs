//! Rich and event-based diagnostic information for eBPF.
//!
//! This is a helper crate to facilitate the build script
//! implementation. Most of the time `clang_args_from_default_env`
//! should be sufficient to compile `bpf-tracing`. You can
//! customize the ring buffer used to copy the tracing events to
//! user space with the following clang arguments:
//! `BPF_TRACING_RINGBUF_SIZE`: determines the size of the ring buffer in bytes, default is 1000.
//! `BPF_TRACING_STR_LEN`: determines the maximum string length for tracing events, default is 128.
//! # Example
//!
//! ```no_run
//! # use std::ffi::OsString;
//! # struct SkeletonBuilder;
//! #
//! # impl SkeletonBuilder {
//! #     fn new() -> Self {
//! #         Self
//! #     }
//! #
//! #     fn source(self, _src: &str) -> Self {
//! #         self
//! #     }
//! #
//! #     fn clang_args(self, _args: Vec<OsString>) -> Self {
//! #         self
//! #     }
//! #
//! #     fn build_and_generate(self, _out: &str) -> Result<(), ()> {
//! #         unimplemented!()
//! #     }
//! # }
//! #
//! # let out = "out";
//! # let src = "src";
//! let mut args = vec![OsString::from("-I"), OsString::from("../include")];
//! args.extend(bpf_include::clang_args_from_default_env(None));
//!
//! SkeletonBuilder::new()
//!     .source(&src)
//!     .clang_args(args)
//!     .build_and_generate(&out)
//!     .unwrap();
//! ```
//!
use std::{env, ffi::OsString, path::Path};
use tracing::{Dispatch, Level, Metadata, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, registry::Registry};

pub mod event;

/// Returns true if `target` is enabled at `level` by this EnvFilter.
fn target_enabled_at(filter: &EnvFilter, target: &'static str, level: Level) -> bool {
    let cs = tracing::callsite!(name: "fake", kind: tracing::metadata::Kind::EVENT, fields: &[]);
    let meta = Metadata::new(
        "probe",
        target,
        level,
        None,
        None,
        None,
        tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(cs)),
        tracing::metadata::Kind::EVENT,
    );

    let dispatch = Dispatch::new(Registry::default().with(filter.clone()));
    dispatch.enabled(&meta)
}

/// Returns the level filter for the given environment variable name.
fn level_from_env(env_var: &str) -> LevelFilter {
    let filter = EnvFilter::builder()
        .with_env_var(env_var)
        .with_default_directive(LevelFilter::OFF.into())
        .from_env_lossy();

    if target_enabled_at(&filter, "bpf", Level::TRACE) {
        LevelFilter::TRACE
    } else if target_enabled_at(&filter, "bpf", Level::DEBUG) {
        LevelFilter::DEBUG
    } else if target_enabled_at(&filter, "bpf", Level::INFO) {
        LevelFilter::INFO
    } else if target_enabled_at(&filter, "bpf", Level::WARN) {
        LevelFilter::WARN
    } else if target_enabled_at(&filter, "bpf", Level::ERROR) {
        LevelFilter::ERROR
    } else {
        LevelFilter::OFF
    }
}

/// Returns the clang arguments used to compile an eBPF program with bpf-tracing.
///
/// The vector contains the path to the include directory along with other clang
/// definitions. The log level is determined by the `RUST_LOG`
/// environment variable.
#[inline]
pub fn clang_args_from_default_env(ring_buf_size: Option<usize>) -> Vec<OsString> {
    let level = level_from_env(EnvFilter::DEFAULT_ENV);

    clang_args(level, ring_buf_size)
}

/// Similar to [`clang_args_from_default_env`], but takes the name of the environment
/// variable that determines the log level.
#[inline]
pub fn clang_args_from_env(env_var: &str, ring_buf_size: Option<usize>) -> Vec<OsString> {
    println!("cargo:rerun-if-env-changed={env_var}");
    let level = level_from_env(env_var);

    clang_args(level, ring_buf_size)
}

/// Similar to [`clang_args_from_default_env`], but takes an explicit tracing [`LevelFilter`].
pub fn clang_args(level: LevelFilter, ring_buf_size: Option<usize>) -> Vec<OsString> {
    let mut args = vec![OsString::from("-I"), OsString::from(include_path_root())];
    let log_level = match level {
        LevelFilter::OFF => 0,
        LevelFilter::ERROR => 1,
        LevelFilter::WARN => 2,
        LevelFilter::INFO => 3,
        LevelFilter::DEBUG => 4,
        LevelFilter::TRACE => 5,
    };
    if log_level == 0 {
        return args;
    }

    let log_level = format!("BPF_TRACING_LEVEL={log_level}");
    args.extend_from_slice(&[OsString::from("-D"), OsString::from(log_level)]);

    if cfg!(feature = "tracing-source-loc") {
        args.extend_from_slice(&[
            OsString::from("-D"),
            OsString::from("BPF_TRACING_SOURCE_LOC=1"),
        ]);
    }

    if let Some(size) = ring_buf_size {
        let size = format!("BPF_TRACING_RINGBUF_SIZE={size}");
        args.extend_from_slice(&[OsString::from("-D"), OsString::from(size)]);
    }

    args
}

/// Returns the root path of the include directory. Note that arguments returned
/// by [`clang_args_from_default_env`] and [`clang_args`] already contain this path.
#[inline]
pub fn include_path_root() -> OsString {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo:rerun-if-changed={:?}", path);
    OsString::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rich_env_var() {
        let env_var = "TEST_VAR";
        let level = temp_env::with_var(env_var, Some("trace,bpf=debug,other_target=warn"), || {
            level_from_env(env_var)
        });

        assert_eq!(level, LevelFilter::DEBUG);
    }

    #[test]
    fn parse_default_rich_env_var() {
        let env_var = "RUST_LOG";
        let clang_args =
            temp_env::with_var(env_var, Some("trace,bpf=debug,other_target=warn"), || {
                clang_args_from_default_env(None)
            });

        assert!(clang_args.contains(&OsString::from("BPF_TRACING_LEVEL=4")));
    }
}
