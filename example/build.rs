use bpf::build::Builder;

fn main() {
    let include_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/include");

    let mut clang_args = vec!["-I".to_string(), include_dir.to_string()];
    let tracing_args = bpf_tracing_include::clang_args_from_default_env()
        .expect("failed to parse log level from RUST_LOG/BPF_LOG");
    clang_args.extend(
        tracing_args
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned()),
    );

    Builder::new().clang_arg(clang_args.into_iter()).build();
}
