use libbpf_cargo::SkeletonBuilder;
use std::collections::HashMap;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Includes the generated skeleton for the eBPF program with the given name.
#[macro_export]
macro_rules! include_bpf {
    ($name:literal) => {
        include!(concat!(env!("OUT_DIR"), "/", $name, ".skel.rs"));
    };
}

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
            pattern: String::from("src/**/*.bpf.c"),
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

    fn path_relative_to_src(path: &Path) -> Option<&Path> {
        let mut components = path.components();
        for c in &mut components {
            if c.as_os_str() == "src" {
                return components.as_path().parent();
            }
        }
        None
    }

    pub fn build(&self) {
        let Some(out_dir) = std::env::var_os("OUT_DIR") else {
            panic!("OUT_DIR must be set to compile eBPF programs.");
        };
        let out_dir = PathBuf::from(&out_dir);

        let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be set in build script");
        let manifest_dir = PathBuf::from(&manifest_dir);

        let pattern = PathBuf::from(&manifest_dir).join(&self.pattern);
        let Some(pattern) = pattern.to_str() else {
            panic!("Invalid eBPF glob pattern: {}", self.pattern);
        };

        let Ok(files) = glob::glob(pattern) else {
            panic!("Invalid eBPF glob pattern: {}", self.pattern);
        };

        let files = files
            .filter_map(|f| match f {
                Ok(file) => Some(file),
                Err(e) => {
                    println!("cargo:warning=Failed to read eBPF source file: {:?}", e);
                    None
                }
            })
            .chain(self.sources.clone().into_iter());

        let mut name_counts: HashMap<String, usize> = HashMap::new();
        let named_files: Vec<(PathBuf, String)> = files
            .filter_map(|file| {
                let Some(name) = file.file_prefix() else {
                    println!("cargo:warning=Invalid eBPF source file name: {:?}", file);
                    return None;
                };
                let name = name.to_string_lossy().into_owned();
                *name_counts.entry(name.clone()).or_insert(0) += 1;
                Some((file, name))
            })
            .collect();

        for (file, name) in named_files {
            println!("cargo:rerun-if-changed={}", file.display());

            let rel_dir = Builder::path_relative_to_src(&file).unwrap_or(Path::new(""));
            let out_subdir = out_dir.join(rel_dir);

            if std::fs::create_dir_all(&out_subdir).is_err() {
                panic!(
                    "Failed to create output directory: {}",
                    out_subdir.display()
                );
            }

            let skel_name = format!("{}.skel.rs", name);
            let out = out_subdir.join(&skel_name);
            let res = SkeletonBuilder::new()
                .source(&file)
                .clang_args(&self.clang_args)
                .build_and_generate(&out);
            if res.is_err() {
                panic!("Failed to compile eBPF source file: {:?}: {:?}", file, res);
            }

            if name_counts.get(&name) == Some(&1) && out_subdir != out_dir {
                let link = out_dir.join(&skel_name);
                if link.symlink_metadata().is_ok() {
                    if let Err(e) = std::fs::remove_file(&link) {
                        panic!("Failed to remove stale symlink {}: {}", link.display(), e);
                    }
                }
                if let Err(e) = symlink(&out, &link) {
                    println!(
                        "cargo:warning=Failed to create symlink {} -> {}: {}",
                        link.display(),
                        out.display(),
                        e
                    );
                }
            }
        }
    }
}

pub fn build() {
    let include_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../example/include");

    let mut clang_args = vec!["-I".to_string(), include_dir.to_string()];

    if cfg!(feature = "tracing") {
        let tracing_args = bpf_tracing_include::clang_args_from_default_env();
        clang_args.extend(
            tracing_args
                .into_iter()
                .map(|a| a.to_string_lossy().into_owned()),
        );
    }

    Builder::new().clang_arg(clang_args.into_iter()).build();
}
