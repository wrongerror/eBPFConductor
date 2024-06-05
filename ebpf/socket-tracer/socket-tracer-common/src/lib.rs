#![no_std]

pub const AF_UNKNOWN: u32 = 0xff;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;
pub const MAX_MSG_SIZE: usize = 30720;
pub const CHUNK_LIMIT: usize = 84;
pub const LOOP_LIMIT: usize = 882;
pub const PROTOCOL_VEC_LIMIT: usize = 3;
pub const CONN_STATS_DATA_THRESHOLD: i64 = 65536;

#[derive(Copy, Clone, Debug)]
#[repr(u64)]
pub enum ControlEventType {
    Open,
    Close,
}

#[derive(Copy, Clone, PartialEq, Debug)]
#[repr(u64)]
pub enum MessageType {
    Unknown,
    Request,
    Response,
}

#[derive(Copy, Clone, PartialEq, Debug)]
#[repr(u64)]
pub enum TrafficDirection {
    Egress,
    Ingress,
}

#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[repr(u64)]
pub enum EndpointRole {
    #[default]
    Unknown = 1,
    Client = 2,
    Server = 4,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(u64)]
pub enum TrafficProtocol {
    #[default]
    Unknown = 0,
    HTTP = 1,
    HTTP2 = 2,
    DNS = 3,
    MySQL = 4,
    PGSQL = 5,
    Redis = 6,
    NATS = 7,
    Kafka = 8,
    AMQP = 9,
    NumProtocols,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ProtocolMessage {
    pub protocol: TrafficProtocol,
    pub msg_type: MessageType,
}

#[derive(Copy, Clone, Debug)]
#[repr(u64)]
pub enum ControlValueIndex {
    TargetTGIDIndex = 0,
    SelfTGIDIndex = 1,
    NumControlValues,
}

#[derive(Copy, Clone, Debug)]
#[repr(u64)]
pub enum SourceFunction {
    SourceFunctionUnknown,
    SyscallAccept,
    SyscallConnect,
    SyscallClose,
    SyscallWrite,
    SyscallRead,
    SyscallSend,
    SyscallRecv,
    SyscallSendTo,
    SyscallRecvFrom,
    SyscallSendMsg,
    SyscallRecvMsg,
    SyscallSendMMsg,
    SyscallRecvMMsg,
    SyscallWriteV,
    SyscallReadV,
    SyscallSendFile,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct Uid {
    pub tgid: u64,
    pub start_time_ticks: u64,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnId {
    // The unique identifier of the pid_tgid.
    pub uid: Uid,
    // The file descriptor to the opened network connection.
    pub fd: i64,
    // Unique id of the conn_id (timestamp).
    pub tsid: u64,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnInfo {
    // The unique identifier of the connection.
    pub id: ConnId,

    // The protocol of the traffic on the connection.
    pub protocol: TrafficProtocol,

    // classify the traffic role of the connection.
    pub role: EndpointRole,

    // The number of bytes written/read on this connection.
    pub write_bytes: i64,
    pub read_bytes: i64,

    // The previously reported values of bytes written/read.
    // Used for determining when to send updated conn_stats values.
    pub prev_reported_bytes: i64,

    // The IP address of the source.
    pub src_addr_in4: u32,
    pub src_addr_in6: [u8; 16usize],
    // The IP address of the destination.
    pub dst_addr_in4: u32,
    pub dst_addr_in6: [u8; 16usize],
    // The family of the socket.
    pub sa_family: u32,
    // The port of the source.
    pub src_port: u32,
    // The port of the destination.
    pub dst_port: u32,
    // How many times traffic inference has been applied on this connection.
    pub protocol_total_count: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketDataEventInner {
    // The timestamp when syscall completed (return probe was triggered).
    pub timestamp_ns: u64,
    // The unique identifier of the connection.
    pub id: ConnId,
    // The protocol of the traffic on the connection.
    pub protocol: TrafficProtocol,
    // The role of the connection (client/server).
    pub role: EndpointRole,
    // The type of the actual data that the msg field encodes, which is used by the caller
    // to determine how to interpret the data.
    pub direction: TrafficDirection,
    // Whether the traffic was collected from an encrypted channel.
    pub ssl: bool,
    // The function that triggered the data collection.
    pub source_function: SourceFunction,
    // A 0-based position number for this event on the connection, in terms of byte position.
    // The position is for the first byte of this message.
    // Note that write/send have separate sequences than read/recv.
    pub position: u64,
    // The size of the original message. We use this to truncate msg field to minimize the amount
    // of data being transferred.
    pub msg_size: u32,
    // The amount of data actually being sent to user space. This may be less than msg_size if
    // data had to be truncated, or if the data was stripped because we only want to send metadata
    // (e.g. if the connection data tracking has been disabled).
    pub msg_buf_size: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketDataEvent {
    pub inner: SocketDataEventInner,
    // The actual data that was collected.
    pub msg: [u8; MAX_MSG_SIZE],
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ConnStatsEvent {
    // The timestamp of the stats event.
    pub timestamp_ns: u64,
    // The unique identifier of the connection.
    pub id: ConnId,

    // The family of the socket.
    pub sa_family: u64,
    // The ip address and port of the connection (source/destination).
    pub src_addr_in4: u32,
    pub src_addr_in6: [u8; 16usize],
    pub src_port: u32,
    pub dst_addr_in4: u32,
    pub dst_addr_in6: [u8; 16usize],
    pub dst_port: u32,
    // The role of the connection (client/server).
    pub role: EndpointRole,
    // The number of bytes written on this connection.
    pub write_bytes: i64,
    // The number of bytes read on this connection.
    pub read_bytes: i64,
    // Bitmask of flags specifying whether conn open or close have been observed.
    pub event_flags: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketControlEvent {
    pub id: ConnId,
    pub event_type: ControlEventType,
    pub sa_family: u64,
    pub timestamp_ns: u64,
    pub source_function: SourceFunction,
    pub role: EndpointRole,

    // Fields for Open Event
    pub src_addr_in4: u32,
    pub src_addr_in6: [u8; 16usize],
    pub src_port: u32,
    pub dst_addr_in4: u32,
    pub dst_addr_in6: [u8; 16usize],
    pub dst_port: u32,

    // Fields for Close Event
    pub write_bytes: i64,
    pub read_bytes: i64,
}
