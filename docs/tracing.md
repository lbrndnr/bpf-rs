# Tracing

This is a tracing facility for eBPF that produces rich, event-based diagnostic information. It efficiently copies tracing events into user space using a ring buffer, and emits them conveniently using the [tracing](https://crates.io/crates/tracing) facility.

## Usage

You can run the example using `RUST_LOG=trace cargo build && sudo -E RUST_LOG=trace ./target/debug/example`. Loading an eBPF program requires privileges, so the binary has to be run as root.

To use it, add `xbpf` to your `Cargo.toml` as both a dependency and a build dependency:
```toml
[dependencies]
xbpf = "0.0.1"

[build-dependencies]
xbpf = "0.0.1"
```

Next, compile your eBPF sources from your `build.rs` script. This picks up every `*.bpf.c` file below `src`, generates a skeleton for each of them, and exports the xBPF headers so your IDE can resolve them:
```rust
fn main() {
    xbpf::build();
}
```

`xbpf::build` reads the `RUST_LOG` environment variable to compile out unneeded logging calls in the eBPF code, since logging is expensive in eBPF. Tracing is off unless `RUST_LOG` enables it for the `bpf` target. Use [`xbpf::build::Builder`](../xbpf/src/build.rs) if you need to pick the level, the sources or the clang arguments yourself, or [`xbpf::build::tracing_clang_args_from_default_env`](../xbpf/src/build.rs) if you drive `SkeletonBuilder` directly.

In your eBPF program, you can now include the [xbpf.h](../xbpf/include/xbpf.h) header and call the tracing macros.
```c
#include "vmlinux.h"
#include "xbpf.h"
#include <bpf/bpf_helpers.h>

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        bpf_start_info_span("sockops");

        bpf_info("Established socket %d", skey.local.port);

        bpf_end_span("sockops");
    }

    return SK_PASS;
}
```

Finally, load the program in your Rust program. `Program::build` starts reading the ring buffer and continuously emits the tracing events, so nothing else is needed:
```rust
xbpf::include_bpf!("monitor");

let mut open_obj = OpenObject::new();
let prog = Program::build(MonitorSkelBuilder::default(), &mut open_obj)?;
```

If you load the object some other way, call `xbpf::tracing::try_init(&obj)?` yourself.

This will yield the following trace:
```
2026-04-20T13:23:27.545062Z  INFO bpf: sockops
2026-04-20T13:23:27.545166Z  INFO bpf: Established socket [127.0.0.1:34812->127.0.0.1:9999]
2026-04-20T13:23:27.545239Z  INFO bpf: Add socket [127.0.0.1:34812->127.0.0.1:9999]
2026-04-20T13:23:27.545345Z  INFO bpf: sockops
2026-04-20T13:23:27.545450Z  INFO bpf: Established socket [127.0.0.1:9999->127.0.0.1:34812]
```

Enable the `tracing-source-loc` feature to have every event carry the file and line it was emitted from, which a subscriber configured `.with_file(true).with_line_number(true)` then prints:
```
2026-04-20T13:23:27.545062Z  INFO bpf: example/src/monitor.bpf.c:34: sockops
2026-04-20T13:23:27.545166Z  INFO bpf: example/src/monitor.bpf.c:50: Established socket [127.0.0.1:34812->127.0.0.1:9999]
```

It is off by default because it adds the file name and line to every event, and therefore takes up more of the ring buffer per event.

## Tuning

The ring buffer holds 8192 bytes by default and each event carries strings of up to 128 bytes. Events emitted while the ring buffer is full are dropped, so size it to fit the largest expected burst with `Builder::tracing_ring_buf_size`. `Builder::tracing_str_len` changes the string length, but note that the user space decoder currently assumes the default of 128 bytes.

## License
This project is licensed under the [MIT license](../LICENSE).
