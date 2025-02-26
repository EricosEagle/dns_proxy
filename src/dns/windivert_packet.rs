use std::borrow::Cow;

use windivert::error::WinDivertError;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PacketSource {
    Original,
    Imposter,
}

pub fn create_windivert_packet_from(
    data: Vec<u8>,
    windivert_packet: &WinDivertPacket<'_, NetworkLayer>,
    packet_direction: PacketDirection,
    packet_source: PacketSource,
) -> Result<WinDivertPacket<'static, NetworkLayer>, WinDivertError> {
    log::trace!("Source packet: {:?}", windivert_packet);

    let mut packet = windivert_packet.clone();
    packet.data = Cow::from(data);
    packet
        .address
        .set_outbound(packet_direction == PacketDirection::Outbound);
    packet
        .address
        .set_impostor(packet_source == PacketSource::Imposter);

    Ok(packet.into_owned())
}
