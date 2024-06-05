use core::slice;

use socket_tracer_common::{MessageType, ProtocolMessage, TrafficProtocol};

fn infer_http_message(buf: &[u8], count: usize) -> MessageType {
    if count < 16 {
        return MessageType::Unknown;
    }

    if buf.starts_with(b"HTTP") {
        return MessageType::Response;
    }
    if buf.starts_with(b"GET") || buf.starts_with(b"HEAD") || buf.starts_with(b"POST") {
        return MessageType::Request;
    }
    if buf.starts_with(b"PUT") || buf.starts_with(b"DELETE") {
        return MessageType::Request;
    }

    MessageType::Unknown
}

pub(crate) fn infer_protocol(buf: *const u8, count: usize) -> ProtocolMessage {
    let buf = unsafe { slice::from_raw_parts(buf, count) };
    let mut inferred_message = ProtocolMessage {
        protocol: TrafficProtocol::Unknown,
        msg_type: MessageType::Unknown,
    };

    match infer_http_message(buf, count) {
        MessageType::Unknown => {}
        msg_type => {
            inferred_message.msg_type = msg_type;
            inferred_message.protocol = TrafficProtocol::HTTP;
        }
    }

    inferred_message
}
