use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsString, fs, path::PathBuf};
use tracing::level_filters::LevelFilter;

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let manifest_dir = PathBuf::from(&manifest_dir);

    let src = manifest_dir.join("tests").join("bpf").join("loop.bpf.c");
    println!("cargo:rerun-if-changed={src:?}");

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script");
    let out_dir = PathBuf::from(&out_dir);
    fs::create_dir_all(&out_dir).unwrap();
    let out = out_dir.join("loop.skel.rs");

    let mut args = vec![OsString::from("-I"), OsString::from("../include")];
    args.extend(bpf_include::clang_args(LevelFilter::DEBUG, None));

    SkeletonBuilder::new()
        .source(&src)
        .clang_args(args)
        .build_and_generate(&out)
        .unwrap();
}
