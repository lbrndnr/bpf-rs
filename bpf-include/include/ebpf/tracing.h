#ifndef __EBPF_TRACING_H__
#define __EBPF_TRACING_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

enum log_level {
    BPF_TRACING_LEVEL_OFF=0,
    BPF_TRACING_LEVEL_ERROR,
    BPF_TRACING_LEVEL_WARN,
    BPF_TRACING_LEVEL_INFO,
    BPF_TRACING_LEVEL_DEBUG,
    BPF_TRACING_LEVEL_TRACE,
};

#ifndef BPF_TRACING_LEVEL
    #define BPF_TRACING_LEVEL BPF_TRACING_LEVEL_OFF
#endif

enum tracing_event_type {
    BPF_TRACING_EVENT_TYPE_MSG = 0,
    BPF_TRACING_EVENT_TYPE_SPAN_START,
    BPF_TRACING_EVENT_TYPE_SPAN_END,
};

#ifndef BPF_TRACING_RINGBUF_SIZE
    #define BPF_TRACING_RINGBUF_SIZE 8192
#endif

#ifndef BPF_TRACING_STR_LEN
    #define BPF_TRACING_STR_LEN 128
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, BPF_TRACING_RINGBUF_SIZE);
} bpf_tracing_events SEC(".maps");

#ifdef BPF_TRACING_SOURCE_LOC
struct bpf_tracing_event {
    __u8 level;
    __u8 kind;
    __u16 cpu;
    char msg[BPF_TRACING_STR_LEN];
    char file[BPF_TRACING_STR_LEN];
    __u32 line;
};

#define BPF_TRACING_EMIT_EVENT(lvl, ty, fmt, ...)                     \
    do {                                                              \
        struct bpf_tracing_event *event;                              \
        event = bpf_ringbuf_reserve(&bpf_tracing_events, sizeof(*event), 0);      \
        if (!event) {                                                 \
            break;                                                    \
        }                                                             \
        event->level = (__u8)(lvl);                                   \
        event->kind = (__u8)(ty);                                     \
        event->cpu = (__u16)(bpf_get_smp_processor_id);               \
        BPF_SNPRINTF(event->msg, BPF_TRACING_STR_LEN, fmt, ##__VA_ARGS__); \
        BPF_SNPRINTF(event->file, BPF_TRACING_STR_LEN, "%s", __FILE__);  \
        event->line = (__u32)__LINE__;                                \
        bpf_ringbuf_submit(event, 0);                                 \
    } while (0)
#else
struct bpf_tracing_event {
    __u8 level;
    __u8 kind;
    __u16 _pad;
    char msg[BPF_TRACING_STR_LEN];
};

#define BPF_TRACING_EMIT_EVENT(lvl, ty, fmt, ...)                     \
    do {                                                              \
        struct bpf_tracing_event *event;                              \
        event = bpf_ringbuf_reserve(&bpf_tracing_events, sizeof(*event), 0);      \
        if (!event) {                                                 \
            break;                                                    \
        }                                                             \
        event->level = (__u8)(lvl);                                   \
        event->kind = (__u8)(ty);                                     \
        BPF_SNPRINTF(event->msg, BPF_TRACING_STR_LEN, fmt, ##__VA_ARGS__); \
        bpf_ringbuf_submit(event, 0);                                 \
    } while (0)
#endif

#if BPF_TRACING_LEVEL == BPF_TRACING_LEVEL_OFF
    #define bpf_end_span(fmt, ...) (0)
#else
    #define bpf_end_span(fmt, ...) BPF_TRACING_EMIT_EVENT(BPF_TRACING_LEVEL_OFF, BPF_TRACING_EVENT_TYPE_SPAN_END, "")
#endif

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

#endif // __EBPF_TRACING_H__
