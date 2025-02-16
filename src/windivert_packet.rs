use std::borrow::Cow;

use windivert::packet::WinDivertPacket;
use windivert::{address::WinDivertAddress, layer::NetworkLayer};
use windivert_sys::ChecksumFlags;

fn initialise_windivert_address(interface_index: u32, is_outbound: bool) -> WinDivertAddress<NetworkLayer> {
    let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };

    // Set address properties
    // According to the docs, Most address fields are ignored by WinDivertSend().
    // The exceptions are Outbound (for WINDIVERT_LAYER_NETWORK only), Impostor, IPChecksum, TCPChecksum, UDPChecksum, Network.IfIdx and Network.SubIfIdx.
    address.set_outbound(is_outbound); // Set to 1 for outbound packets/event, 0 for inbound or otherwise.
    address.set_impostor(false); // An impostor packet is any packet injected by another driver rather than originating from the network or Windows TCP/IP stack
    address.set_ip_checksum(true); // Set to 1 if the IPv4 checksum is valid, 0 otherwise.
    address.set_tcp_checksum(false); // Not using TCP
    address.set_udp_checksum(true); // UDP Checksum is valid

    address.set_interface_index(interface_index);
    // Didn't find a way to access the subinterface index, hopefully it's not needed

    address
}

pub fn create_windivert_packet_from(
    data: Vec<u8>,
    windivert_packet: &WinDivertPacket<'_, NetworkLayer>,
    is_outbound: bool,
) -> Result<WinDivertPacket<'static, NetworkLayer>, String> {
    let mut packet = windivert_packet.clone();
    packet.data = Cow::from(data);

    packet.address.set_outbound(is_outbound);
    packet.recalculate_checksums(ChecksumFlags::default()).map_err(|e| e.to_string())?;

    Ok(packet.into_owned())
}
