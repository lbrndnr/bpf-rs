use libbpf_cargo::SkeletonBuilder;
use std::path::{Path, PathBuf};

pub struct Builder {
    /// The glob pattern used to find source files.
    pattern: String,

    /// The list of explicitely specified source files.
    sources: Vec<PathBuf>,

    /// Additional clang arguments that apply to all jobs.
    clang_args: Vec<String>,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            pattern: String::from("*.bpf.rs"),
            sources: Vec::new(),
            clang_args: Vec::new(),
        }
    }

    pub fn sources_with_suffix<S: ToString>(&mut self, suffix: S) -> &mut Self {
        self.pattern = format!("*.{}", suffix.to_string());
        self
    }

    pub fn source<P: AsRef<Path>>(&mut self, file: P) -> &mut Self {
        self.sources.push(file.as_ref().to_path_buf());
        self
    }

    pub fn clang_arg<A: AsRef<str>, CA: Iterator<Item = A>>(&mut self, args: CA) -> &mut Self {
        self.clang_args
            .extend(args.into_iter().map(|a| a.as_ref().to_string()));
        self
    }

    pub fn build(&self) {
        let Some(out_dir) = std::env::var_os("OUT_DIR") else {
            panic!("OUT_DIR must be set to compile eBPF programs.");
        };
        let out_dir = PathBuf::from(&out_dir);
        if std::fs::create_dir_all(&out_dir).is_err() {
            panic!("Failed to create OUT_DIR: {}", out_dir.display());
        }

        let Ok(files) = glob::glob(&self.pattern) else {
            panic!("Invalid eBPF glob pattern: {}", self.pattern);
        };
        for file in files {
            let Ok(file) = file else {
                println!("cargo:warning=Failed to read eBPF source file: {:?}", file);
                continue;
            };
            let Some(name) = file.file_prefix() else {
                println!("cargo:warning=Invalid eBPF source file name: {:?}", file);
                continue;
            };

            let out = out_dir.clone().join(format!("{:?}.skel.rs", name));
            let res = SkeletonBuilder::new()
                .source(&file)
                .clang_args(&self.clang_args)
                .build_and_generate(&out);
            if res.is_err() {
                panic!("Failed to compile eBPF source file: {:?}: {:?}", file, res);
            }
        }
    }
}
