#![no_std]
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const MAX_CONNECTIONS: u32 = 100000;

pub const TCP_ESTABLISHED: i32 = 1;
pub const TCP_SYN_SENT: i32 = 2;
pub const TCP_SYN_RECV: i32 = 3;
pub const TCP_FIN_WAIT1: i32 = 4;
pub const TCP_FIN_WAIT2: i32 = 5;
pub const TCP_TIME_WAIT: i32 = 6;
pub const TCP_CLOSE: i32 = 7;
pub const TCP_CLOSE_WAIT: i32 = 8;
pub const TCP_LAST_ACK: i32 = 9;
pub const TCP_LISTEN: i32 = 10;
pub const TCP_CLOSING: i32 = 11;
pub const TCP_NEW_SYN_RECV: i32 = 12;
pub const TCP_MAX_STATES: i32 = 13;

pub const INET_SOCK_SKADDR_OFFSET: usize = 8;
pub const INET_SOCK_NEWSTATE_OFFSET: usize = 20;

pub const CONNECTION_ROLE_UNKNOWN: u32 = 0;
pub const CONNECTION_ROLE_CLIENT: u32 = 1;
pub const CONNECTION_ROLE_SERVER: u32 = 2;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SockInfo {
    pub id: u32,
    pub pid: u32,
    pub is_active: u32,
    pub role: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockInfo {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnectionKey {
    pub id: u32,
    pub pid: u32,
    pub src_addr: u32,
    pub src_port: u32,
    pub dest_addr: u32,
    pub dest_port: u32,
    pub role: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionKey {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_active: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionStats {}
