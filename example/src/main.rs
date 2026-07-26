#![allow(unused_imports)]
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::{mem::MaybeUninit, thread::sleep, time::Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

bpf::include_bpf!("syscall_trace");

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let mut open_obj = MaybeUninit::uninit();
    let skel_builder = SyscallTraceSkelBuilder::default();
    let open_skel = skel_builder.open(&mut open_obj)?;
    let skel = open_skel.load()?;

    bpf_tracing::try_init(skel.object())?;

    let _link = skel.progs.trace_syscall.attach()?;

    println!("Tracing syscalls... press Ctrl-C to stop.");
    loop {
        sleep(Duration::from_secs(1));
    }
}
