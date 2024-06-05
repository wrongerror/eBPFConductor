#![no_std]
#![no_main]

use core::{cmp::PartialEq, fmt::Debug};

use aya_ebpf::{
    cty::{size_t, ssize_t},
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user,
    },
    macros::{kprobe, kretprobe, map},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::{debug, info};

use socket_tracer_common::{
    AF_INET, AF_INET6, AF_UNKNOWN, CHUNK_LIMIT, CONN_STATS_DATA_THRESHOLD, ConnId,
    ConnInfo, ConnStatsEvent, ControlEventType, ControlValueIndex, EndpointRole,
    LOOP_LIMIT,
    MAX_MSG_SIZE, MessageType, PROTOCOL_VEC_LIMIT, SocketControlEvent, SocketDataEvent, SourceFunction, TrafficDirection,
    TrafficDirection::{Egress, Ingress}, TrafficProtocol, Uid,
};

use crate::{
    utils::{bpf_probe_read_buf_with_size, get_tgid_start_time},
    vmlinux::{
        iovec, mmsghdr, sa_family_t, sock, sock_common, sockaddr, sockaddr_in, sockaddr_in6,
        user_msghdr,
    },
};

mod protocols;
mod types;
mod utils;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

pub const MAX_MAP_ENTRIES: u32 = 128 * 1024;

#[map(name = "sk_ctrl_events")]
static mut SOCKET_CONTROL_EVENTS: PerfEventArray<SocketControlEvent> =
    PerfEventArray::<SocketControlEvent>::with_max_entries(0, 0);

#[map(name = "sk_data_events")]
static mut SOCKET_DATA_EVENTS: PerfEventArray<SocketDataEvent> =
    PerfEventArray::<SocketDataEvent>::with_max_entries(0, 0);

#[map(name = "conn_stat_events")]
static mut CONN_STATS_EVENTS: PerfEventArray<ConnStatsEvent> =
    PerfEventArray::<ConnStatsEvent>::with_max_entries(0, 0);

#[map(name = "ctrl_map")]
static mut CONTROL_MAP: PerCpuArray<u64> =
    PerCpuArray::<u64>::with_max_entries(TrafficProtocol::NumProtocols as u32, 0);

#[map(name = "ctrl_values")]
static mut CONTROL_VALUES: PerCpuArray<i64> =
    PerCpuArray::<i64>::with_max_entries(ControlValueIndex::NumControlValues as u32, 0);

#[map(name = "sock_data_buf")]
static mut SOCKET_DATA_EVENT_BUFFER: PerCpuArray<SocketDataEvent> =
    PerCpuArray::<SocketDataEvent>::with_max_entries(1, 0);

#[map(name = "conn_stats_buf")]
static mut CONN_STATS_EVENT_BUFFER: PerCpuArray<ConnStatsEvent> =
    PerCpuArray::<ConnStatsEvent>::with_max_entries(1, 0);

#[map(name = "conn_info")]
static mut CONN_INFO_MAP: HashMap<u64, ConnInfo> =
    HashMap::<u64, ConnInfo>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "conn_disabled")]
static mut CONN_DISABLED_MAP: HashMap<u64, u64> =
    HashMap::<u64, u64>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "accept_args")]
static mut ACTIVE_ACCEPT_MAP: HashMap<u64, types::AcceptArgs> =
    HashMap::<u64, types::AcceptArgs>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "conn_args")]
static mut ACTIVE_CONNECT_MAP: HashMap<u64, types::ConnectArgs> =
    HashMap::<u64, types::ConnectArgs>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "write_args")]
static mut ACTIVE_WRITE_MAP: HashMap<u64, types::DataArgs> =
    HashMap::<u64, types::DataArgs>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "read_args")]
static mut ACTIVE_READ_MAP: HashMap<u64, types::DataArgs> =
    HashMap::<u64, types::DataArgs>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "sendfile_args")]
static mut ACTIVE_SENDFILE_MAP: HashMap<u64, types::SendfileArgs> =
    HashMap::<u64, types::SendfileArgs>::with_max_entries(MAX_MAP_ENTRIES, 0);

#[map(name = "close_args")]
static mut ACTIVE_CLOSE_MAP: HashMap<u64, types::CloseArgs> =
    HashMap::<u64, types::CloseArgs>::with_max_entries(MAX_MAP_ENTRIES, 0);

// helper functions

fn gen_tgid_fd(tgid: u32, fd: i32) -> u64 {
    ((tgid as u64) << 32) | (fd as u64)
}

fn gen_tsid() -> u64 {
    unsafe { bpf_ktime_get_ns() as u64 }
}

fn init_conn_id(tgid: u32, fd: i32) -> ConnId {
    ConnId {
        uid: Uid {
            tgid: tgid as u64,
            start_time_ticks: get_tgid_start_time().unwrap_or(0),
        },
        fd: fd as i64,
        tsid: gen_tsid(),
    }
}

fn init_conn_info(tgid: u32, fd: i32, conn_info: &mut ConnInfo) {
    conn_info.id = init_conn_id(tgid, fd);
    conn_info.role = EndpointRole::Unknown;
    conn_info.sa_family = AF_UNKNOWN;
}

fn get_or_create_conn_info(tgid: u32, fd: i32) -> Result<ConnInfo, i64> {
    let tgid_fd = gen_tgid_fd(tgid, fd);
    let mut conn_info = ConnInfo::default();
    init_conn_info(tgid, fd, &mut conn_info);

    match unsafe { CONN_INFO_MAP.get(&tgid_fd) } {
        Some(&info) => Ok(info),
        None => {
            unsafe {
                CONN_INFO_MAP.insert(&tgid_fd, &conn_info, 0)?;
            }
            Ok(conn_info)
        }
    }
}

fn populate_socket_data_event(
    src_fn: SourceFunction,
    direction: TrafficDirection,
    conn_info: &ConnInfo,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    event.inner.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.inner.source_function = src_fn;
    event.inner.direction = direction;
    event.inner.id = conn_info.id;
    event.inner.protocol = conn_info.protocol;
    event.inner.role = conn_info.role;
    event.inner.position = match direction {
        Egress => conn_info.write_bytes as u64,
        Ingress => conn_info.read_bytes as u64,
    };

    Ok(0)
}

fn populate_conn_stats_event(conn_info: ConnInfo) -> Result<ConnStatsEvent, i64> {
    let idx: u32 = 0;
    let mut event = unsafe { *CONN_STATS_EVENT_BUFFER.get_ptr_mut(idx).ok_or(1)? };

    event.id = conn_info.id;
    event.src_addr_in4 = conn_info.src_addr_in4;
    event.src_addr_in6 = conn_info.src_addr_in6;
    event.src_port = conn_info.src_port;
    event.dst_addr_in4 = conn_info.dst_addr_in4;
    event.dst_addr_in6 = conn_info.dst_addr_in6;
    event.dst_port = conn_info.dst_port;
    event.role = conn_info.role;
    event.write_bytes = conn_info.write_bytes;
    event.read_bytes = conn_info.read_bytes;
    event.event_flags = 0;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

    Ok(event)
}

// filter functions

fn should_trace_sockaddr_family(sa_family: u32) -> bool {
    return sa_family == AF_UNKNOWN || sa_family == AF_INET || sa_family == AF_INET6;
}

fn should_trace_conn(conn_info: &ConnInfo) -> bool {
    return should_trace_sockaddr_family(conn_info.sa_family);
}

fn should_trace_protocol_data(conn_info: ConnInfo) -> bool {
    match conn_info.protocol {
        TrafficProtocol::Unknown => false,
        _ => {
            let protocol = conn_info.protocol as u32;
            let idx: u64 = 0;
            let control_val = match unsafe { CONTROL_MAP.get(protocol) } {
                Some(&val) => val,
                None => idx,
            };
            control_val & conn_info.role as u64 != 0
        }
    }
}

fn is_self_tgid(tgid: u32) -> bool {
    let idx = ControlValueIndex::SelfTGIDIndex as u32;
    let agent_tgid_val = unsafe { CONTROL_VALUES.get(idx) };
    match agent_tgid_val {
        Some(&agent_tgid) => agent_tgid as u32 == tgid,
        None => false,
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq)]
pub enum TargetTgidMatchResult {
    Unspecified,
    All,
    Matched,
    Unmatched,
}

fn match_trace_tgid(tgid: u32) -> TargetTgidMatchResult {
    let idx = ControlValueIndex::TargetTGIDIndex as u32;
    let target_tgid_val = unsafe { CONTROL_VALUES.get(idx) };
    match target_tgid_val {
        Some(&target_tgid) => {
            if target_tgid <= 0 {
                TargetTgidMatchResult::All
            } else if target_tgid as u32 == tgid {
                TargetTgidMatchResult::Matched
            } else {
                TargetTgidMatchResult::Unmatched
            }
        }
        None => TargetTgidMatchResult::Unspecified,
    }
}

fn update_traffic_class(
    conn_info: &mut ConnInfo,
    direction: TrafficDirection,
    buf: *const u8,
    count: usize,
) -> Result<u32, i64> {
    conn_info.protocol_total_count += 1;

    let inferred_protocol = protocols::infer_protocol(buf, count);
    match inferred_protocol.protocol {
        TrafficProtocol::Unknown => {
            return Ok(0);
        }
        protocol => {
            conn_info.protocol = protocol;
            if conn_info.role == EndpointRole::Unknown
                && inferred_protocol.msg_type != MessageType::Unknown
            {
                //    direction  req_resp_type  => role
                //    ------------------------------------
                //    Egress    Request       => Client
                //    Egress    Response      => Server
                //    Ingress   Request       => Server
                //    Ingress   Response      => Client
                conn_info.role = if (direction == Egress)
                    ^ (inferred_protocol.msg_type == MessageType::Response)
                {
                    EndpointRole::Client
                } else {
                    EndpointRole::Server
                };
            }
        }
    }

    Ok(0)
}

fn parse_sock_data(sk: *const sock, conn_info: &mut ConnInfo) -> Result<u32, i64> {
    let sk_common =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common).map_err(|e| e)? };

    // read connection data
    match sk_common.skc_family as u32 {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dst_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let src_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            let dst_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            conn_info.sa_family = AF_INET;
            conn_info.src_addr_in4 = src_addr;
            conn_info.dst_addr_in4 = dst_addr;
            conn_info.src_port = src_port as u32;
            conn_info.dst_port = dst_port as u32;
        }
        AF_INET6 => {
            let src_addr = unsafe { sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 };
            let dst_addr = unsafe { sk_common.skc_v6_daddr.in6_u.u6_addr8 };
            let src_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            let dst_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            conn_info.sa_family = AF_INET6;
            conn_info.src_addr_in6 = src_addr;
            conn_info.dst_addr_in6 = dst_addr;
            conn_info.src_port = src_port as u32;
            conn_info.dst_port = dst_port as u32;
        }
        _ => return Err(1),
    }

    Ok(0)
}

fn parse_sockaddr_data(
    ctx: &ProbeContext,
    sockaddr: *const sockaddr,
    conn_info: &mut ConnInfo,
) -> Result<u32, i64> {
    conn_info.sa_family =
        unsafe { bpf_probe_read_user(&(*sockaddr).sa_family as *const u16)? as u32 };
    info!(ctx, "Parsed sockaddr: sa_family: {}", conn_info.sa_family);
    match conn_info.sa_family {
        AF_INET => {
            let sa_ptr_in = unsafe { sockaddr as *const sockaddr_in };
            let sa_in = unsafe { bpf_probe_read_user(sa_ptr_in).map_err(|e| e)? };
            conn_info.dst_addr_in4 = u32::from_be(sa_in.sin_addr.s_addr);
            conn_info.dst_port = u16::from_be(sa_in.sin_port) as u32;
            info!(
                ctx,
                "AF_INET src address: {:i}, dest address: {:i}",
                conn_info.src_addr_in4,
                conn_info.dst_addr_in4,
            );
        }
        AF_INET6 => {
            let sa_ptr_in6 = unsafe { sockaddr as *const sockaddr_in6 };
            let sa_in6 = unsafe { bpf_probe_read_user(sa_ptr_in6).map_err(|e| e)? };
            conn_info.dst_addr_in6 = unsafe { sa_in6.sin6_addr.in6_u.u6_addr8 };
            conn_info.dst_port = u16::from_be(sa_in6.sin6_port) as u32;
            info!(
                ctx,
                "AF_INET6 src address: {:i}, dest address: {:i}",
                conn_info.src_addr_in6,
                conn_info.dst_addr_in6,
            )
        }
        _ => return Err(1),
    }
    Ok(0)
}

// perf submit functions

#[repr(C)]
struct OpenEventArgs {
    tgid: u32,
    fd: i32,
    sockaddr: *const sockaddr,
    sk: *const sock,
    role: EndpointRole,
    source_fn: SourceFunction,
}

fn submit_open_event(ctx: &ProbeContext, args: &OpenEventArgs) -> Result<u32, i64> {
    let mut conn_info = ConnInfo::default();
    init_conn_info(args.tgid, args.fd, &mut conn_info);
    conn_info.role = args.role;

    info!(
        ctx,
        "Submitting open event for tgid: {} start_time_ticks: {} fd: {} tsid: {}",
        conn_info.id.uid.tgid,
        conn_info.id.uid.start_time_ticks,
        conn_info.id.fd,
        conn_info.id.tsid,
    );

    if !args.sk.is_null() {
        parse_sock_data(args.sk, &mut conn_info)?;
    } else if !args.sockaddr.is_null() {
        parse_sockaddr_data(ctx, args.sockaddr, &mut conn_info)?;
    }

    let tgid_fd = gen_tgid_fd(args.tgid, args.fd);
    unsafe {
        CONN_INFO_MAP.insert(&tgid_fd, &conn_info, 0)?;
    }
    if !should_trace_sockaddr_family(conn_info.sa_family) {
        return Ok(0);
    }

    let socket_control_event = SocketControlEvent {
        id: conn_info.id,
        event_type: ControlEventType::Open,
        sa_family: conn_info.sa_family as u64,
        source_function: args.source_fn,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        src_addr_in4: conn_info.src_addr_in4,
        src_addr_in6: conn_info.src_addr_in6,
        src_port: conn_info.src_port,
        dst_addr_in4: conn_info.dst_addr_in4,
        dst_addr_in6: conn_info.dst_addr_in6,
        dst_port: conn_info.dst_port,
        role: conn_info.role,
        write_bytes: 0,
        read_bytes: 0,
    };

    unsafe {
        SOCKET_CONTROL_EVENTS.output(ctx, &socket_control_event, 0);
    }
    Ok(0)
}

fn submit_close_event(
    ctx: &ProbeContext,
    conn_info: &ConnInfo,
    src_fn: SourceFunction,
) -> Result<u32, i64> {
    let socket_control_event = SocketControlEvent {
        id: conn_info.id,
        event_type: ControlEventType::Close,
        sa_family: conn_info.sa_family as u64,
        source_function: src_fn,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        src_addr_in4: conn_info.src_addr_in4,
        src_addr_in6: conn_info.src_addr_in6,
        src_port: conn_info.src_port,
        dst_addr_in4: conn_info.dst_addr_in4,
        dst_addr_in6: conn_info.dst_addr_in6,
        dst_port: conn_info.dst_port,
        role: conn_info.role,
        write_bytes: conn_info.write_bytes,
        read_bytes: conn_info.read_bytes,
    };

    unsafe {
        SOCKET_CONTROL_EVENTS.output(ctx, &socket_control_event, 0);
    }
    Ok(0)
}

fn perf_submit_buf(
    ctx: &ProbeContext,
    buf: *const u8,
    mut buf_size: usize,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    event.inner.msg_size = buf_size as u32;

    if buf_size == 0 {
        return Ok(0);
    }

    let buf_size_minus_1 = buf_size - 1;

    buf_size = buf_size_minus_1 + 1;

    let mut amount_copied = 0;
    if buf_size_minus_1 < MAX_MSG_SIZE {
        unsafe {
            bpf_probe_read_buf_with_size(buf, event.msg.as_mut(), buf_size)?;
        }
        amount_copied = buf_size;
    } else if buf_size_minus_1 < 0x7fffffff {
        unsafe {
            bpf_probe_read_buf_with_size(buf, event.msg.as_mut(), MAX_MSG_SIZE)?;
        }
        amount_copied = MAX_MSG_SIZE;
    }

    if amount_copied > 0 {
        event.inner.msg_buf_size = amount_copied as u32;
        unsafe {
            SOCKET_DATA_EVENTS.output(ctx, event, 0);
        }
    }
    Ok(0)
}

fn submit_data_event(
    ctx: &ProbeContext,
    buf: *const u8,
    buf_size: usize,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    let mut bytes_submitted: usize = 0;
    for i in 0..CHUNK_LIMIT {
        let bytes_remaining = buf_size - bytes_submitted;
        let current_size: usize = if bytes_remaining > MAX_MSG_SIZE && i != CHUNK_LIMIT - 1 {
            MAX_MSG_SIZE
        } else {
            bytes_remaining
        };
        let current_buf = unsafe { buf.add(bytes_submitted) };
        perf_submit_buf(ctx, current_buf, current_size, event)?;

        bytes_submitted += current_size;
    }

    Ok(0)
}

fn submit_data_event_iovecs(
    ctx: &ProbeContext,
    iov: *const iovec,
    iovlen: u64,
    total_size: usize,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    let mut bytes_sent = 0;

    for i in 0..LOOP_LIMIT.min(iovlen as usize) {
        if bytes_sent >= total_size {
            break;
        }

        let iov_ptr = unsafe { iov.add(i) };
        let iov_cpy = match unsafe { bpf_probe_read_kernel(iov_ptr) } {
            Ok(iov) => iov,
            Err(err) => return Err(err as i64),
        };

        let bytes_remaining = total_size - bytes_sent;
        let iov_size = bytes_remaining.min(iov_cpy.iov_len as usize);

        perf_submit_buf(ctx, iov_cpy.iov_base as *const u8, iov_size, event)?;
        bytes_sent += iov_size;

        event.inner.position += iov_size as u64;
    }

    Ok(0)
}

// process functions
fn process_syscall_connect(
    ctx: &ProbeContext,
    pid_tgid: u64,
    args: &types::ConnectArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let retval: i32 = ctx.ret().ok_or(1u32)?;

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    if args.fd < 0 {
        return Ok(0);
    }

    if retval < 0 {
        return Ok(0);
    }

    let open_event_args = OpenEventArgs {
        tgid,
        fd: args.fd,
        sockaddr: args.sockaddr,
        sk: core::ptr::null(),
        role: EndpointRole::Client,
        source_fn: SourceFunction::SyscallConnect,
    };

    submit_open_event(ctx, &open_event_args)?;

    Ok(0)
}

fn process_syscall_accept(
    ctx: &ProbeContext,
    pid_tgid: u64,
    args: &types::AcceptArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let ret_fd: i32 = ctx.ret().ok_or(1u32)?;

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    if ret_fd < 0 {
        return Ok(0);
    }

    let open_event_args = OpenEventArgs {
        tgid,
        fd: ret_fd,
        sockaddr: args.sockaddr,
        sk: args.sock,
        role: EndpointRole::Server,
        source_fn: SourceFunction::SyscallAccept,
    };

    submit_open_event(ctx, &open_event_args)?;

    Ok(0)
}

fn process_syscall_close(
    ctx: &ProbeContext,
    pid_tgid: u64,
    args: &types::CloseArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let retval: i32 = ctx.ret().ok_or(1u32)?;

    if args.fd < 0 {
        return Ok(0);
    }

    if retval < 0 {
        return Ok(0);
    }

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    let tgid_fd = gen_tgid_fd(tgid, args.fd);
    let conn_info = unsafe { CONN_INFO_MAP.get(&tgid_fd).ok_or(1)? };

    if should_trace_sockaddr_family(conn_info.sa_family)
        || conn_info.write_bytes > 0
        || conn_info.read_bytes > 0
    {
        submit_close_event(ctx, &conn_info, SourceFunction::SyscallClose)?;

        let mut event = populate_conn_stats_event(*conn_info)?;
        event.event_flags = event.event_flags | (1 << 1);
        unsafe {
            CONN_STATS_EVENTS.output(ctx, &event, 0);
        }
    }

    unsafe {
        CONN_INFO_MAP.remove(&tgid_fd)?;
    }

    Ok(0)
}

fn should_send_data(
    tgid: u32,
    conn_disabled_tsid: u64,
    force_trace_tgid: bool,
    conn_info: ConnInfo,
) -> bool {
    if is_self_tgid(tgid) {
        return false;
    }

    if conn_info.id.tsid <= conn_disabled_tsid {
        return false;
    }

    return force_trace_tgid || should_trace_protocol_data(conn_info);
}

fn update_conn_stats(
    ctx: &ProbeContext,
    conn_info: &mut ConnInfo,
    direction: TrafficDirection,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    match direction {
        Egress => {
            conn_info.write_bytes += bytes_count as i64;
        }
        Ingress => {
            conn_info.read_bytes += bytes_count as i64;
        }
    }

    let total_bytes = conn_info.write_bytes + conn_info.read_bytes;
    let meets_activity_threshold =
        total_bytes >= conn_info.prev_reported_bytes + CONN_STATS_DATA_THRESHOLD;

    if meets_activity_threshold {
        let event = populate_conn_stats_event(*conn_info)?;
        unsafe {
            CONN_STATS_EVENTS.output(ctx, &event, 0);
        }
        conn_info.prev_reported_bytes = total_bytes;
    }
    Ok(0)
}

#[repr(C)]
struct ProcessDataArgs {
    vecs: bool,
    pid_tgid: u64,
    direction: TrafficDirection,
    bytes_count: ssize_t,
}

fn process_data(
    ctx: &ProbeContext,
    args: &types::DataArgs,
    extra_args: &ProcessDataArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (extra_args.pid_tgid >> 32) as u32;

    if !extra_args.vecs && args.buf.is_null() {
        return Ok(0);
    }

    if extra_args.vecs && (args.iov.is_null() || args.iovlen <= 0) {
        return Ok(0);
    }

    if args.fd < 0 {
        return Ok(0);
    }

    if extra_args.bytes_count <= 0 {
        return Ok(0);
    }

    let match_result = match_trace_tgid(tgid);

    if match_result == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    let force_trace_tgid = match match_result {
        TargetTgidMatchResult::Matched => true,
        _ => false,
    };

    let mut conn_info = get_or_create_conn_info(tgid, args.fd)?;

    if !should_trace_conn(&conn_info) {
        return Ok(0);
    }

    let tgid_fd = gen_tgid_fd(tgid, args.fd);
    let conn_disabled = unsafe { CONN_DISABLED_MAP.get(&tgid_fd) };
    let conn_disabled_tsid = match conn_disabled {
        Some(&tsid) => tsid,
        None => 0,
    };

    match extra_args.vecs {
        true => {
            for i in 0..PROTOCOL_VEC_LIMIT.min(args.iovlen as usize) {
                let iov_ptr = unsafe { args.iov.add(i) };
                let iov = match unsafe { bpf_probe_read_kernel(iov_ptr as *const iovec) } {
                    Ok(iov) => iov,
                    Err(err) => return Err(err as i64),
                };
                let buf_size = extra_args.bytes_count.min(iov.iov_len as ssize_t);
                if buf_size != 0 {
                    update_traffic_class(
                        &mut conn_info,
                        extra_args.direction,
                        iov.iov_base as *const u8,
                        buf_size as usize,
                    )?;
                    break;
                }
            }
        }
        false => {
            update_traffic_class(
                &mut conn_info,
                extra_args.direction,
                args.buf,
                extra_args.bytes_count as usize,
            )?;
        }
    }

    if should_send_data(tgid, conn_disabled_tsid, force_trace_tgid, conn_info) {
        let idx: u32 = 0;
        let event_ptr_mut = unsafe { SOCKET_DATA_EVENT_BUFFER.get_ptr_mut(idx).ok_or(1)? };
        let event_ref_mut = unsafe { event_ptr_mut.as_mut().ok_or(1)? };
        populate_socket_data_event(
            args.source_function,
            extra_args.direction,
            &conn_info,
            event_ref_mut,
        )?;
        match extra_args.vecs {
            true => {
                submit_data_event_iovecs(
                    ctx,
                    args.iov,
                    args.iovlen,
                    extra_args.bytes_count as usize,
                    event_ref_mut,
                )?;
            }
            false => {
                submit_data_event(
                    ctx,
                    args.buf,
                    extra_args.bytes_count as usize,
                    event_ref_mut,
                )?;
            }
        }
    }

    update_conn_stats(
        ctx,
        &mut conn_info,
        extra_args.direction,
        extra_args.bytes_count,
    )?;

    Ok(0)
}

fn process_syscall_data(
    ctx: &ProbeContext,
    pid_tgid: u64,
    direction: TrafficDirection,
    args: &types::DataArgs,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    let extra_args = ProcessDataArgs {
        vecs: false,
        pid_tgid,
        direction,
        bytes_count,
    };
    process_data(ctx, args, &extra_args)
}

fn process_syscall_data_vecs(
    ctx: &ProbeContext,
    pid_tgid: u64,
    direction: TrafficDirection,
    args: &types::DataArgs,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    let extra_args = ProcessDataArgs {
        vecs: true,
        pid_tgid,
        direction,
        bytes_count,
    };
    process_data(ctx, args, &extra_args)
}

fn process_syscall_sendfile(
    ctx: &ProbeContext,
    id: u64,
    args: &types::SendfileArgs,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    let tgid = (id >> 32) as u32;

    if args.out_fd < 0 {
        return Ok(0);
    }

    if bytes_count <= 0 {
        return Ok(0);
    }

    let match_result = match_trace_tgid(tgid);
    if match_result == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }
    let force_trace_tgid = match_result == TargetTgidMatchResult::Matched;

    let mut conn_info = get_or_create_conn_info(tgid, args.out_fd)?;
    if !should_trace_conn(&conn_info) {
        return Ok(0);
    }

    let tgid_fd = gen_tgid_fd(tgid, args.out_fd);
    let conn_disabled_tsid = unsafe {
        match CONN_DISABLED_MAP.get(&tgid_fd) {
            Some(&tsid) => tsid,
            None => 0,
        }
    };

    if should_send_data(tgid, conn_disabled_tsid, force_trace_tgid, conn_info) {
        let idx: u32 = 0;
        let event_ptr_mut = unsafe { SOCKET_DATA_EVENT_BUFFER.get_ptr_mut(idx).ok_or(1)? };
        let event_ref_mut = unsafe { event_ptr_mut.as_mut().ok_or(1)? };

        populate_socket_data_event(
            SourceFunction::SyscallSendFile,
            Egress,
            &conn_info,
            event_ref_mut,
        )?;

        event_ref_mut.inner.position = conn_info.write_bytes as u64;
        event_ref_mut.inner.msg_size = bytes_count as u32;
        event_ref_mut.inner.msg_buf_size = 0;
        unsafe {
            SOCKET_DATA_EVENTS.output(ctx, event_ref_mut, 0);
        }
    }

    update_conn_stats(ctx, &mut conn_info, Egress, bytes_count)?;

    Ok(0)
}

// kprobes

// #[kprobe]
// pub fn entry_connect(ctx: ProbeContext) -> u32 {
//     try_entry_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_connect(ctx: ProbeContext) -> Result<u32, i64> {
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let sockaddr: *const sockaddr = ctx.arg(1).ok_or(1)?;
//     let pid_tgid = bpf_get_current_pid_tgid();
//
//     let connect_args = types::ConnectArgs { fd, sockaddr };
//     unsafe {
//         ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
//     }
//
//     Ok(0)
// }
//
// #[kretprobe]
// pub fn ret_connect(ctx: ProbeContext) -> u32 {
//     try_ret_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_connect(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid).ok_or(1)? };
//     let res = process_syscall_connect(&ctx, pid_tgid, connect_args);
//     unsafe {
//         ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
//     }
//     res
// }

#[kprobe]
pub fn entry_accept(ctx: ProbeContext) -> u32 {
    try_entry_accept(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_accept(ctx: ProbeContext) -> Result<u32, i64> {
    let sockaddr: *const sockaddr = ctx.arg(1).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    let accept_args = types::AcceptArgs {
        sockaddr,
        sock: core::ptr::null(),
    };

    unsafe {
        ACTIVE_ACCEPT_MAP.insert(&pid_tgid, &accept_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_accept(ctx: ProbeContext) -> u32 {
    try_ret_accept(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_accept(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let accept_args = unsafe { ACTIVE_ACCEPT_MAP.get(&pid_tgid).ok_or(1)? };
    let res = process_syscall_accept(&ctx, pid_tgid, accept_args);

    unsafe {
        ACTIVE_ACCEPT_MAP.remove(&pid_tgid)?;
    }

    res
}

// #[kprobe]
// pub fn entry_write(ctx: ProbeContext) -> u32 {
//     try_entry_write(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_write(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_write called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let buf: *const u8 = ctx.arg(1).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = types::DataArgs {
//         source_function: SourceFunction::SyscallWrite,
//         sock_event: false,
//         fd,
//         buf,
//         iov: core::ptr::null_mut(),
//         iovlen: 0,
//         msg_len: 0,
//     };
//     ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_write(ctx: ProbeContext) -> u32 {
//     try_ret_write(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_write(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count: ssize_t = ctx.ret().ok_or(1)?;
//
//     let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_data(&ctx, pid_tgid, Egress, data_args, bytes_count)?;
//
//     ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_send(ctx: ProbeContext) -> u32 {
//     try_entry_send(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_send(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_send called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let buf: *const u8 = ctx.arg(1).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = types::DataArgs {
//         source_function: SourceFunction::SyscallSend,
//         sock_event: false,
//         fd,
//         buf,
//         iov: core::ptr::null_mut(),
//         iovlen: 0,
//         msg_len: 0,
//     };
//     ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_send(ctx: ProbeContext) -> u32 {
//     try_ret_send(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_send(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count: ssize_t = ctx.ret().ok_or(1)?;
//
//     let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_data(&ctx, pid_tgid, Egress, data_args, bytes_count)?;
//
//     ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_sendto(ctx: ProbeContext) -> u32 {
//     try_entry_sendto(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_sendto(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_sendto called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let buf: *const u8 = ctx.arg(1).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = types::DataArgs {
//         source_function: SourceFunction::SyscallSendTo,
//         sock_event: false,
//         fd,
//         buf,
//         iov: core::ptr::null_mut(),
//         iovlen: 0,
//         msg_len: 0,
//     };
//     ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_sendto(ctx: ProbeContext) -> u32 {
//     try_ret_sendto(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_sendto(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count: ssize_t = ctx.ret().ok_or(1)?;
//
//     let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_data(&ctx, pid_tgid, Egress, data_args, bytes_count)?;
//
//     ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_recvfrom(ctx: ProbeContext) -> u32 {
//     try_entry_recvfrom(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_recvfrom(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_recvfrom called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let buf: *const u8 = ctx.arg(1).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = types::DataArgs {
//         source_function: SourceFunction::SyscallRecvFrom,
//         sock_event: false,
//         fd,
//         buf,
//         iov: core::ptr::null_mut(),
//         iovlen: 0,
//         msg_len: 0,
//     };
//     ACTIVE_READ_MAP.insert(&pid_tgid, &data_args, 0)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_recvfrom(ctx: ProbeContext) -> u32 {
//     try_ret_recvfrom(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_recvfrom(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count: ssize_t = ctx.ret().ok_or(1)?;
//
//     let data_args = unsafe { ACTIVE_READ_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_data(&ctx, pid_tgid, Ingress, data_args, bytes_count)?;
//     ACTIVE_READ_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_sendmsg(ctx: ProbeContext) -> u32 {
//     try_entry_sendmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_sendmsg called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let msghdr: *const user_msghdr = ctx.arg(1).ok_or(1)?;
//     let pid_tgid = bpf_get_current_pid_tgid();
//
//     if msghdr.is_null() {
//         return Ok(0);
//     }
//
//     unsafe {
//         if !(*msghdr).msg_name.is_null() {
//             let connect_args = types::ConnectArgs {
//                 sockaddr: (*msghdr).msg_name as *const sockaddr,
//                 fd,
//             };
//             ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
//         }
//     }
//
//     unsafe {
//         let data_args = types::DataArgs {
//             source_function: SourceFunction::SyscallSendMsg,
//             sock_event: true,
//             fd,
//             buf: core::ptr::null(),
//             iov: (*msghdr).msg_iov,
//             iovlen: (*msghdr).msg_iovlen,
//             msg_len: 0,
//         };
//         ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
//     }
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_sendmsg(ctx: ProbeContext) -> u32 {
//     try_ret_sendmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count = ctx.ret().ok_or(1)?;
//
//     let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
//     if let Some(&_args) = connect_args {
//         ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
//     }
//     let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count)?;
//     ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_sendmmsg(ctx: ProbeContext) -> u32 {
//     try_entry_sendmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_sendmmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_sendmmsg called");
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let msgvec: *const mmsghdr = ctx.arg(1).ok_or(1)?;
//     let vlen: u32 = ctx.arg(2).ok_or(1)?;
//
//     if !msgvec.is_null() && vlen >= 1 {
//         let header_msg = unsafe { *msgvec };
//         if header_msg.msg_hdr.msg_name.is_null() {
//             let connect_args = types::ConnectArgs {
//                 sockaddr: header_msg.msg_hdr.msg_name as *const sockaddr,
//                 fd,
//             };
//             ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
//         }
//
//         let data_args = types::DataArgs {
//             source_function: SourceFunction::SyscallSendMMsg,
//             sock_event: false,
//             fd,
//             buf: core::ptr::null(),
//             iov: header_msg.msg_hdr.msg_iov,
//             iovlen: header_msg.msg_hdr.msg_iovlen,
//             msg_len: header_msg.msg_len,
//         };
//
//         ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
//     }
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_sendmmsg(ctx: ProbeContext) -> u32 {
//     try_ret_sendmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_sendmmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let num_msgs: u32 = ctx.ret().ok_or(1)?;
//
//     let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
//     if let Some(&_args) = connect_args {
//         ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
//     }
//     let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
//     let bytes_count = data_args.msg_len;
//     if num_msgs > 0 {
//         process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count as ssize_t)?;
//     }
//     ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_recvmsg(ctx: ProbeContext) -> u32 {
//     try_entry_recvmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_recvmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_recvmsg called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let msghdr: *const user_msghdr = ctx.arg(1).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//
//     if !msghdr.is_null() {
//         unsafe {
//             if !(*msghdr).msg_name.is_null() {
//                 let connect_args = types::ConnectArgs {
//                     sockaddr: (*msghdr).msg_name as *const sockaddr,
//                     fd,
//                 };
//                 ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
//             }
//             let data_args = types::DataArgs {
//                 source_function: SourceFunction::SyscallRecvMsg,
//                 sock_event: false,
//                 fd,
//                 buf: core::ptr::null(),
//                 iov: (*msghdr).msg_iov,
//                 iovlen: (*msghdr).msg_iovlen,
//                 msg_len: 0,
//             };
//
//             ACTIVE_READ_MAP.insert(&pid_tgid, &data_args, 0)?;
//         }
//     }
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_recvmsg(ctx: ProbeContext) -> u32 {
//     try_ret_recvmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_recvmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count = ctx.ret().ok_or(1)?;
//
//     let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
//     if let Some(&_args) = connect_args {
//         ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
//     }
//     let data_args = unsafe { ACTIVE_READ_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_data_vecs(&ctx, pid_tgid, Ingress, data_args, bytes_count)?;
//     ACTIVE_READ_MAP.remove(&pid_tgid)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_recvmmsg(ctx: ProbeContext) -> u32 {
//     try_entry_recvmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_recvmmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_recvmmsg called");
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let msgvec: *const mmsghdr = ctx.arg(1).ok_or(1)?;
//     let vlen: u32 = ctx.arg(2).ok_or(1)?;
//
//     if !msgvec.is_null() && vlen >= 1 {
//         let header_msg = unsafe { *msgvec };
//         if !header_msg.msg_hdr.msg_name.is_null() {
//             let connect_args = types::ConnectArgs {
//                 sockaddr: header_msg.msg_hdr.msg_name as *const sockaddr,
//                 fd,
//             };
//             ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
//         }
//
//         let data_args = types::DataArgs {
//             source_function: SourceFunction::SyscallRecvMMsg,
//             sock_event: false,
//             fd,
//             buf: core::ptr::null(),
//             iov: header_msg.msg_hdr.msg_iov,
//             iovlen: header_msg.msg_hdr.msg_iovlen,
//             msg_len: header_msg.msg_len,
//         };
//
//         ACTIVE_READ_MAP.insert(&pid_tgid, &data_args, 0)?;
//     }
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_recvmmsg(ctx: ProbeContext) -> u32 {
//     try_ret_recvmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_recvmmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let num_msgs: u32 = ctx.ret().ok_or(1)?;
//
//     let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
//     if let Some(&_args) = connect_args {
//         ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
//     }
//     let data_args = unsafe { ACTIVE_READ_MAP.get(&pid_tgid).ok_or(1)? };
//     let bytes_count: u32 = data_args.msg_len;
//     if num_msgs > 0 {
//         process_syscall_data_vecs(&ctx, pid_tgid, Ingress, data_args, bytes_count as ssize_t)?;
//     }
//     ACTIVE_READ_MAP.remove(&pid_tgid)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_writev(ctx: ProbeContext) -> u32 {
//     try_entry_writev(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_writev(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_writev called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let iov: *mut iovec = ctx.arg(1).ok_or(1)?;
//     let iovlen: u64 = ctx.arg(2).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = types::DataArgs {
//         source_function: SourceFunction::SyscallWriteV,
//         sock_event: false,
//         fd,
//         buf: core::ptr::null(),
//         iov,
//         iovlen,
//         msg_len: 0,
//     };
//     ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_writev(ctx: ProbeContext) -> u32 {
//     try_ret_writev(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_writev(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count = ctx.ret().ok_or(1)?;
//     let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
//
//     if data_args.sock_event {
//         process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count)?;
//     }
//
//     ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_readv(ctx: ProbeContext) -> u32 {
//     try_entry_readv(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_readv(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_readv called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let iov: *mut iovec = ctx.arg(1).ok_or(1)?;
//     let iovlen: u64 = ctx.arg(2).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = types::DataArgs {
//         source_function: SourceFunction::SyscallReadV,
//         sock_event: false,
//         fd,
//         buf: core::ptr::null(),
//         iov,
//         iovlen,
//         msg_len: 0,
//     };
//     ACTIVE_READ_MAP.insert(&pid_tgid, &data_args, 0)?;
//
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_readv(ctx: ProbeContext) -> u32 {
//     try_ret_readv(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_readv(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count = ctx.ret().ok_or(1)?;
//     let data_args = unsafe { ACTIVE_READ_MAP.get(&pid_tgid).ok_or(1)? };
//
//     if data_args.sock_event {
//         process_syscall_data_vecs(&ctx, pid_tgid, Ingress, data_args, bytes_count)?;
//     }
//
//     ACTIVE_READ_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_close(ctx: ProbeContext) -> u32 {
//     try_entry_close(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_close(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_close called");
//     let fd: i32 = ctx.arg(0).ok_or(1)?;
//     let close_args = types::CloseArgs { fd };
//     ACTIVE_CLOSE_MAP.insert(&bpf_get_current_pid_tgid(), &close_args, 0)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_close(ctx: ProbeContext) -> u32 {
//     try_ret_close(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_close(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let close_args = unsafe { ACTIVE_CLOSE_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_close(&ctx, pid_tgid, close_args)?;
//
//     ACTIVE_CLOSE_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_sendfile(ctx: ProbeContext) -> u32 {
//     try_entry_sendfile(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_sendfile(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function syscalls:sys_enter_sendfile called");
//     let out_fd: i32 = ctx.arg(0).ok_or(1)?;
//     let in_fd: i32 = ctx.arg(1).ok_or(1)?;
//     let count: size_t = ctx.arg(3).ok_or(1)?;
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let sendfile_args = types::SendfileArgs {
//         out_fd,
//         in_fd,
//         count,
//     };
//     ACTIVE_SENDFILE_MAP.insert(&pid_tgid, &sendfile_args, 0)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_sendfile(ctx: ProbeContext) -> u32 {
//     try_ret_sendfile(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_sendfile(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let bytes_count: ssize_t = ctx.ret().ok_or(1)?;
//     let sendfile_args = unsafe { ACTIVE_SENDFILE_MAP.get(&pid_tgid).ok_or(1)? };
//     process_syscall_sendfile(&ctx, pid_tgid, sendfile_args, bytes_count)?;
//     ACTIVE_SENDFILE_MAP.remove(&pid_tgid)?;
//     Ok(0)
// }
//
// #[kprobe]
// pub fn ret_sock_alloc(ctx: ProbeContext) -> u32 {
//     try_ret_sock_alloc(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_ret_sock_alloc(ctx: ProbeContext) -> Result<u32, i64> {
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let sk: *const sock = ctx.ret().ok_or(1)?;
//     let accept_args = ACTIVE_ACCEPT_MAP.get_ptr_mut(&pid_tgid).ok_or(1)?;
//     unsafe {
//         if (*accept_args).sock.is_null() {
//             (*accept_args).sock = sk;
//         }
//     }
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_security_socket_sendmsg(ctx: ProbeContext) -> u32 {
//     try_entry_security_socket_sendmsg(ctx)
//         .unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_security_socket_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function security_socket_sendmsg called");
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = ACTIVE_WRITE_MAP.get_ptr_mut(&pid_tgid).ok_or(1)?;
//     unsafe { (*data_args).sock_event = true }
//     Ok(0)
// }
//
// #[kprobe]
// pub fn entry_security_socket_recvmsg(ctx: ProbeContext) -> u32 {
//     try_entry_security_socket_recvmsg(ctx)
//         .unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
// }
//
// fn try_entry_security_socket_recvmsg(ctx: ProbeContext) -> Result<u32, i64> {
//     info!(&ctx, "function security_socket_recvmsg called");
//
//     let pid_tgid = bpf_get_current_pid_tgid();
//     let data_args = ACTIVE_READ_MAP.get_ptr_mut(&pid_tgid).ok_or(1)?;
//     unsafe { (*data_args).sock_event = true }
//     Ok(0)
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
