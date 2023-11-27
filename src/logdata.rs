use serde::{Serialize};

#[derive(Serialize)]
pub struct LogData {
    pub(crate) source: String,
    pub(crate) destination: String,
    pub(crate) ja3: String,
    pub(crate) packet_size: usize,
    pub(crate) is_handshake: bool,
    pub(crate) ethernet_frame_size: usize,
    pub(crate) is_syn: bool,
    pub(crate) is_fin: bool,
    pub(crate) is_rst: bool,
}