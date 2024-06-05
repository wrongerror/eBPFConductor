use socket_tracer_common::SourceFunction;

use crate::vmlinux::{iovec, sock, sockaddr};

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ConnectArgs {
    pub fd: i32,
    pub sockaddr: *const sockaddr,
}

unsafe impl Sync for ConnectArgs {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct AcceptArgs {
    pub sockaddr: *const sockaddr,
    pub sock: *const sock,
}

unsafe impl Sync for AcceptArgs {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct DataArgs {
    // Represents the function from which this argument group originates.
    pub source_function: SourceFunction,

    // Did the data event call sock_sendmsg/sock_recvmsg.
    // Used to filter out read/write and readv/writev calls that are not to sockets.
    pub sock_event: bool,

    pub fd: i32,

    // For send()/recv()/write()/read().
    pub buf: *const u8,

    // For sendmsg()/recvmsg()/writev()/readv().
    pub iov: *mut iovec,
    pub iovlen: u64,

    // For sendmmsg()
    pub msg_len: u32,
}

unsafe impl Sync for DataArgs {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct CloseArgs {
    pub fd: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SendfileArgs {
    pub out_fd: i32,
    pub in_fd: i32,
    pub count: usize,
}
