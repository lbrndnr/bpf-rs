use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, Skel, SkelBuilder},
};
use std::{
    io::Write,
    mem::MaybeUninit,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

/// A `tracing_subscriber` writer that buffers everything in memory instead
/// of writing to stdout/stderr, so tests can inspect what was logged.
#[derive(Clone, Default)]
struct InMemoryWriter(Arc<Mutex<Vec<u8>>>);

impl InMemoryWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("log output is valid utf-8")
    }
}

impl Write for InMemoryWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for InMemoryWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// Tests in the nested `root` module load and run real eBPF programs, which
// requires root (or equivalent capabilities). CI runs
// `cargo test -- --skip ':root:'`, which matches on the fully-qualified
// `tests::root::...` test path, to exclude them from the unprivileged test
// run.
mod tests {
    use super::*;

    mod root {
        use super::*;

        include!(concat!(env!("OUT_DIR"), "/loop.skel.rs"));

        #[test]
        fn loop_iterations_are_traced_in_order() {
            let writer = InMemoryWriter::default();
            tracing_subscriber::fmt()
                .with_max_level(Level::DEBUG)
                .with_writer(writer.clone())
                .with_ansi(false)
                .init();

            let mut open_obj = MaybeUninit::uninit();
            let skel_builder = LoopSkelBuilder::default();
            let open_skel = skel_builder.open(&mut open_obj).expect("open skel");
            let skel = open_skel.load().expect("load skel");
            bpf::tracing::try_init(skel.object()).expect("bpf::tracing init");

            // `trace_loop` is a BPF_PROG_TYPE_SYSCALL program: it isn't
            // attached to anything, it's invoked directly via BPF_PROG_RUN.
            skel.progs
                .trace_loop
                .test_run(ProgramInput::default())
                .expect("test run");

            let log = wait_for_events(&writer, 1000, Duration::from_secs(5));

            let numbers: Vec<u32> = log
                .lines()
                .filter_map(|line| line.rsplit_once("bpf: asdf qwer asdf qwer "))
                .filter_map(|(_, msg)| msg.trim().parse::<u32>().ok())
                .collect();

            assert_eq!(numbers, (0..1000).collect::<Vec<u32>>());
        }

        fn wait_for_events(writer: &InMemoryWriter, expected: usize, timeout: Duration) -> String {
            let start = Instant::now();
            loop {
                let log = writer.contents();
                let seen = log.lines().filter(|line| line.contains("bpf: ")).count();
                if seen >= expected || start.elapsed() > timeout {
                    return log;
                }
            }
        }
    }
}
