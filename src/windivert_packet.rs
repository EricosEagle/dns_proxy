use std::borrow::Cow;

use windivert::error::WinDivertError;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;

pub fn create_windivert_packet_from(
    data: Vec<u8>,
    windivert_packet: &WinDivertPacket<'_, NetworkLayer>,
    is_outbound: bool,
    is_imposter: bool,
) -> Result<WinDivertPacket<'static, NetworkLayer>, WinDivertError> {
    log::trace!("Source packet: {:?}", windivert_packet);

    let mut packet = windivert_packet.clone();
    packet.data = Cow::from(data);
    packet.address.set_outbound(is_outbound);
    packet.address.set_impostor(is_imposter);

    Ok(packet.into_owned())
}
