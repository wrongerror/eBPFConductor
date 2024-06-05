use std::{mem, ptr};
use std::net::Ipv4Addr;

use aya::{Bpf, include_bytes_aligned};
use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, info, warn};
use tokio::signal;

use socket_tracer_common::SocketControlEvent;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/socket-tracer"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/socket-tracer"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let programs = vec![
        // ("entry_connect", "__sys_connect"),
        // ("ret_connect", "__sys_connect"),
        ("entry_accept", "__sys_accept4"),
        ("ret_accept", "__sys_accept4"),
    ];

    for (prog_name, func_name) in programs {
        let program: &mut KProbe = bpf.program_mut(prog_name).unwrap().try_into()?;
        program.load()?;
        program.attach(func_name, 0)?;
    }

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let sk_ctrl_events_map = bpf.take_map("sk_ctrl_events").unwrap();
    let mut events = AsyncPerfEventArray::try_from(sk_ctrl_events_map)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let sk_ctrl_event =
                        unsafe { ptr::read_unaligned(buf.as_ptr() as *const SocketControlEvent) };

                    debug!("sk_ctrl_event: {:?}", sk_ctrl_event);
                    let dst_ipaddr4 = Ipv4Addr::from(sk_ctrl_event.dst_addr_in4);
                    debug!("dst_addr_in4: {}", dst_ipaddr4);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
