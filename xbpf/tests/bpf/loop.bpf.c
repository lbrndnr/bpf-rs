#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xbpf/tracing.h"

char LICENSE[] SEC("license") = "GPL";

SEC("syscall")
int trace_loop(void *ctx) {
    for (int i = 0; i < 1000; i++) {
        bpf_debug("asdf qwer asdf qwer %d", i);
    }

    return 0;
}
