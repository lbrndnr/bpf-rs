/*
 * xbpf.h - rich, event-based diagnostics for eBPF programs.
 *
 * Include this header to emit diagnostic events from an eBPF program. The
 * events are written into a ring buffer, read by the `xbpf` crate on the user
 * space side, and re-emitted there as `tracing` events.
 *
 * Which macros compile to anything is decided at build time through
 * BPF_TRACING_LEVEL, because tracing is expensive in eBPF: every event costs a
 * ring buffer reservation and a BPF_SNPRINTF call. Everything above the
 * configured level expands to (0) and leaves no trace in the program the
 * verifier sees. The `xbpf` build script derives the level from RUST_LOG, so
 * this normally doesn't have to be set by hand.
 */
#ifndef __XBPF_TRACING_H__
#define __XBPF_TRACING_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Verbosity levels, ordered from least to most verbose. These are also the
 * values written into the `level` field of an event. */
#define BPF_TRACING_LEVEL_OFF   0
#define BPF_TRACING_LEVEL_ERROR 1
#define BPF_TRACING_LEVEL_WARN  2
#define BPF_TRACING_LEVEL_INFO  3
#define BPF_TRACING_LEVEL_DEBUG 4
#define BPF_TRACING_LEVEL_TRACE 5

/* The most verbose level that is compiled in. Tracing is off unless the build
 * defines this, so a program that includes this header without being built
 * through `xbpf` pays nothing. */
#ifndef BPF_TRACING_LEVEL
    #define BPF_TRACING_LEVEL BPF_TRACING_LEVEL_OFF
#endif

/* What an event does to the trace: emit a message, open a span, or close the
 * innermost open span. Everything emitted between a start and an end on the
 * same CPU is nested inside that span. */
enum tracing_event_type {
    BPF_TRACING_EVENT_TYPE_MSG = 0,
    BPF_TRACING_EVENT_TYPE_SPAN_START,
    BPF_TRACING_EVENT_TYPE_SPAN_END,
};

/* Size of the ring buffer in bytes. Must be a power of two multiple of the page
 * size. Events emitted while it is full are dropped, so this bounds the burst
 * of events that can be absorbed before user space catches up. */
#ifndef BPF_TRACING_RING_BUF_SIZE
    #define BPF_TRACING_RING_BUF_SIZE 8192
#endif

/* Length of the strings an event carries, in bytes. Longer messages and file
 * names are truncated. Since the strings are inlined into the event, raising
 * this also raises how much of the ring buffer each event occupies.
 *
 * Note that the user space decoder assumes the default of 128. */
#ifndef BPF_TRACING_STR_LEN
    #define BPF_TRACING_STR_LEN 128
#endif

/* The ring buffer events are copied to user space through. `xbpf` finds it by
 * this name, so it must not be renamed. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BPF_TRACING_RING_BUF_SIZE);
} bpf_tracing_events SEC(".maps");

#ifdef BPF_TRACING_SOURCE_LOC
/* One record in the ring buffer. This variant carries the source location of
 * the macro that emitted it, which the `tracing-source-loc` feature of `xbpf`
 * enables. It costs BPF_TRACING_STR_LEN + 4 bytes per event. */
struct bpf_tracing_event {
    __u8 level;
    __u8 kind;
    __u16 cpu;
    char msg[BPF_TRACING_STR_LEN];
    char file[BPF_TRACING_STR_LEN];
    __u32 line;
};

/* Formats `fmt` and submits it as an event of level `lvl` and type `ty`. The
 * event is dropped if the ring buffer is full, since an eBPF program has
 * nowhere to block. */
#define BPF_TRACING_EMIT_EVENT(lvl, ty, fmt, ...)                     \
    do {                                                              \
        struct bpf_tracing_event *event;                              \
        event = bpf_ringbuf_reserve(&bpf_tracing_events, sizeof(*event), 0);      \
        if (!event) {                                                 \
            break;                                                    \
        }                                                             \
        event->level = (__u8)(lvl);                                   \
        event->kind = (__u8)(ty);                                     \
        event->cpu = (__u16)bpf_get_smp_processor_id();               \
        BPF_SNPRINTF(event->msg, BPF_TRACING_STR_LEN, fmt, ##__VA_ARGS__); \
        BPF_SNPRINTF(event->file, BPF_TRACING_STR_LEN, "%s", __FILE__);  \
        event->line = (__u32)__LINE__;                                \
        bpf_ringbuf_submit(event, 0);                                 \
    } while (0)
#else
/* One record in the ring buffer, without a source location. */
struct bpf_tracing_event {
    __u8 level;
    __u8 kind;
    __u16 cpu;
    char msg[BPF_TRACING_STR_LEN];
};

/* Formats `fmt` and submits it as an event of level `lvl` and type `ty`. The
 * event is dropped if the ring buffer is full, since an eBPF program has
 * nowhere to block. */
#define BPF_TRACING_EMIT_EVENT(lvl, ty, fmt, ...)                     \
    do {                                                              \
        struct bpf_tracing_event *event;                              \
        event = bpf_ringbuf_reserve(&bpf_tracing_events, sizeof(*event), 0);      \
        if (!event) {                                                 \
            break;                                                    \
        }                                                             \
        event->level = (__u8)(lvl);                                   \
        event->kind = (__u8)(ty);                                     \
        event->cpu = (__u16)bpf_get_smp_processor_id();               \
        BPF_SNPRINTF(event->msg, BPF_TRACING_STR_LEN, fmt, ##__VA_ARGS__); \
        bpf_ringbuf_submit(event, 0);                                 \
    } while (0)
#endif

/* Closes the innermost span on this CPU whose name matches `fmt`, along with
 * every span opened inside it. Pass the same format string and arguments that
 * opened the span.
 *
 * Compiled in whenever tracing is on at all, so that a span is never left open
 * by a build that filtered out its start. */
#if BPF_TRACING_LEVEL == BPF_TRACING_LEVEL_OFF
    #define bpf_end_span(fmt, ...) (0)
#else
    #define bpf_end_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_OFF, BPF_TRACING_EVENT_TYPE_SPAN_END, fmt, ##__VA_ARGS__)
#endif

/* Emits a message, or opens a span, at the given level. Both take a
 * BPF_SNPRINTF format string and its arguments, and expand to (0) if the build
 * filtered the level out. A span stays open until the next bpf_end_span on the
 * same CPU. */
#if BPF_TRACING_LEVEL >= BPF_TRACING_LEVEL_ERROR
    #define bpf_error(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_ERROR, BPF_TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_error_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_ERROR, BPF_TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_error(fmt, ...) (0)
    #define bpf_start_error_span(fmt, ...) (0)
#endif

#if BPF_TRACING_LEVEL >= BPF_TRACING_LEVEL_WARN
    #define bpf_warn(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_WARN, BPF_TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_warn_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_WARN, BPF_TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_warn(fmt, ...) (0)
    #define bpf_start_warn_span(fmt, ...) (0)
#endif

#if BPF_TRACING_LEVEL >= BPF_TRACING_LEVEL_INFO
    #define bpf_info(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_INFO, BPF_TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_info_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_INFO, BPF_TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_info(fmt, ...) (0)
    #define bpf_start_info_span(fmt, ...) (0)
#endif

#if BPF_TRACING_LEVEL >= BPF_TRACING_LEVEL_DEBUG
    #define bpf_debug(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_DEBUG, BPF_TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_debug_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_DEBUG, BPF_TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_debug(fmt, ...) (0)
    #define bpf_start_debug_span(fmt, ...) (0)
#endif

#if BPF_TRACING_LEVEL >= BPF_TRACING_LEVEL_TRACE
    #define bpf_trace(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_TRACE, BPF_TRACING_EVENT_TYPE_MSG, fmt, ##__VA_ARGS__)
    #define bpf_start_trace_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_TRACE, BPF_TRACING_EVENT_TYPE_SPAN_START, fmt, ##__VA_ARGS__)
#else
    #define bpf_trace(fmt, ...) (0)
    #define bpf_start_trace_span(fmt, ...) (0)
#endif

#endif // __XBPF_TRACING_H__
