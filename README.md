# xBPF

[![Crates.io][crates-badge]][crates-url]
[![GPL-v3 licensed][gpl-badge]][gpl-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/xbpf.svg
[crates-url]: https://crates.io/crates/xbpf
[gpl-badge]: https://img.shields.io/badge/License-MIT-blue.svg
[gpl-url]: LICENSE
[actions-badge]: https://github.com/lbrndnr/xbpf/actions/workflows/ci.yml/badge.svg
[actions-url]: https://github.com/lbrndnr/xbpf/actions/workflows/ci.yml

xBPF (eXtended BPF) is a high-level eBPF library for Rust. Its main goal is an ergonomic and light-weight interface to eBPF. Using it should make the learning curve for beginners a bit more manageable, and make advanced users more productive.

<img width="1536" height="1024" alt="xbpf" src="https://github.com/user-attachments/assets/5259abf5-9bcb-48ff-a6c4-7461f5571bd7" />

It builds on [libbpf-rs](https://github.com/libbpf/libbpf-rs) and adds the parts every eBPF project ends up writing itself:

* **Building** — one call in a `build.rs` compiles every `*.bpf.c` file below `src`, generates a skeleton for it, and exports the headers your IDE needs.
* **Loading** — `Program::build` opens and loads a generated skeleton in one step.
* **Tracing** — the macros of [`xbpf.h`](xbpf/include/xbpf.h) emit diagnostics from eBPF that surface as ordinary [tracing](https://crates.io/crates/tracing) events. See [docs/tracing.md](docs/tracing.md).

Compiling eBPF programs requires `bpftool` on your `PATH`, and loading them requires privileges.

## Example

```rust
xbpf::include_bpf!("syscall_trace");

let mut open_obj = OpenObject::new();
let prog = Program::build(SyscallTraceSkelBuilder::default(), &mut open_obj)?;
let _link = prog.skel.progs.trace_syscall.attach()?;
```

See [example](example) for the full program, and run it with `RUST_LOG=info cargo build && sudo -E RUST_LOG=info ./target/debug/example`. `RUST_LOG` matters at build time too, since that is when the tracing macros are compiled in or out.

## License
This project is licensed under the [MIT license](LICENSE).
