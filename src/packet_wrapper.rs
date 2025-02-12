use etherparse::{NetSlice, SlicedPacket, TransportSlice};

#[derive(Clone, Debug)]
pub struct DnsPacketWrapper {
    buf: Vec<u8>,
}

// Since the wrapper hasn't implemented WinDivertHelperParsePacket
// it is easier to parse the packet ourselves
fn get_udp_packet_slices<'a>(buf: &'a [u8]) -> Result<SlicedPacket<'a>, String> {
    let slices = match SlicedPacket::from_ip(&buf) {
        Ok(slices) => slices,
        Err(e) => {
            return Err(format!("Failed to parse packet: {}", e));
        }
    };

    log::trace!("Raw Packet: {:#x?}", buf);
    log::trace!("Net Slice: {:?}", slices.net);
    log::trace!("Transport Slice: {:?}", slices.transport);
    if !matches!(slices.net, Some(NetSlice::Ipv4(_)))
        || !matches!(slices.transport, Some(TransportSlice::Udp(_)))
    {
        return Err("Packet is not IPv4 or UDP".to_string());
    }

    Ok(slices)
}

impl From<&[u8]> for DnsPacketWrapper {
    fn from(buf: &[u8]) -> Self {
        Self { buf: buf.to_vec() }
    }
}

impl From<Vec<u8>> for DnsPacketWrapper {
    fn from(buf: Vec<u8>) -> Self {
        Self { buf }
    }
}

// Couldn't store these references in the struct because of lifetime issues
// so I made them into functions
impl DnsPacketWrapper {
    pub fn udp_payload_from_slices<'a>(slices: &SlicedPacket<'a>) -> Result<&'a [u8], String> {
        match slices.transport {
            Some(TransportSlice::Udp(ref udp)) => Ok(udp.payload()),
            _ => Err("Packet is not UDP".to_string()),
        }
    }

    pub fn dns_packet_from_slices<'a>(
        slices: &SlicedPacket<'a>,
    ) -> Result<dns_parser::Packet<'a>, String> {
        let udp_payload = Self::udp_payload_from_slices(slices)?;
        Self::dns_packet_from_payload(udp_payload)
    }

    pub fn dns_packet_from_payload<'a>(
        payload: &'a [u8],
    ) -> Result<dns_parser::Packet<'a>, String> {
        dns_parser::Packet::parse(payload).map_err(|e| e.to_string())
    }

    pub fn slices<'a>(&'a self) -> Result<SlicedPacket<'a>, String> {
        get_udp_packet_slices(&self.buf)
    }

    pub fn udp_payload<'a>(&'a self) -> Result<&'a [u8], String> {
        let slices = self.slices()?;
        Self::udp_payload_from_slices(&slices)
    }

    pub fn dns_packet<'a>(&'a self) -> Result<dns_parser::Packet<'a>, String> {
        let udp_payload = self.udp_payload()?;
        Self::dns_packet_from_payload(udp_payload)
    }
}
