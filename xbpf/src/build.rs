use libbpf_cargo::SkeletonBuilder;
use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
};

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
    clang_args: Vec<OsString>,
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

    pub fn clang_arg<A: AsRef<OsStr>, CA: Iterator<Item = A>>(&mut self, args: CA) -> &mut Self {
        self.clang_args
            .extend(args.into_iter().map(|a| a.as_ref().to_os_string()));
        self
    }

    pub fn dump_kernel_btf() -> OsString {
        let out_dir = Builder::get_env_var("OUT_DIR");
        let include_dir = out_dir.join("include");

        let vmlinux_path = include_dir.join("vmlinux.h");
        if vmlinux_path.exists() {
            return include_dir.into_os_string();
        }

        if Command::new("bpftool").arg("--version").output().is_err() {
            panic!("bpftool is required to dump kernel BTF but was not found on PATH");
        }

        let output = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .unwrap_or_else(|e| panic!("Failed to run bpftool: {e}"));
        if !output.status.success() {
            panic!(
                "bpftool btf dump failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        if std::fs::create_dir_all(&include_dir).is_err() {
            panic!(
                "Failed to create include directory: {}",
                include_dir.display()
            );
        }

        std::fs::write(&vmlinux_path, output.stdout)
            .unwrap_or_else(|e| panic!("Failed to write {:?}: {e}", vmlinux_path));
        include_dir.into_os_string()
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

    fn get_env_var(name: &str) -> PathBuf {
        let Some(out_dir) = env::var_os(&name) else {
            panic!("{name} must be set to compile eBPF programs.");
        };
        PathBuf::from(&out_dir)
    }

    pub fn build(&self) {
        let out_dir = Builder::get_env_var("OUT_DIR");
        let manifest_dir = Builder::get_env_var("CARGO_MANIFEST_DIR");

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
                        panic!("Failed to remove stale symlink {:?}: {}", link, e);
                    }
                }
                if let Err(e) = symlink(&out, &link) {
                    println!(
                        "cargo:warning=Failed to create symlink {:?} -> {:?}: {}",
                        link, out, e
                    );
                }
            }
        }
    }
}

pub fn build() {
    let mut clang_args = vec![OsString::from("-I"), Builder::dump_kernel_btf()];

    if cfg!(feature = "tracing") {
        let tracing_args = xbpf_include::clang_args_from_default_env(None);
        clang_args.extend(tracing_args.into_iter().map(|a| a.to_os_string()));
    }

    Builder::new().clang_arg(clang_args.into_iter()).build();
}
