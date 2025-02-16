use std::net::IpAddr;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};

#[derive(Clone, Debug)]
pub struct DnsPacketWrapper {
    source_ip: IpAddr,
    dest_ip: IpAddr,
    source_port: u16,
    dest_port: u16,
    udp_payload: Vec<u8>,
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

    if !matches!(slices.net, Some(NetSlice::Ipv4(_)) | Some(NetSlice::Ipv6(_)))
        || !matches!(slices.transport, Some(TransportSlice::Udp(_)))
    {
        return Err("Packet is not IPv4/IPv6 or UDP".to_string());
    }

    Ok(slices)
}

fn dns_wrapper_from_payload<'a>(
    payload: &'a [u8],
) -> Result<dns_parser::Packet<'a>, String> {
    dns_parser::Packet::parse(payload).map_err(|e| e.to_string())
}

fn udp_payload_from_slices<'a>(slices: &SlicedPacket<'a>) -> Result<&'a [u8], String> {
    match slices.transport {
        Some(TransportSlice::Udp(ref udp)) => Ok(udp.payload()),
        _ => Err("Packet is not UDP".to_string()),
    }
}

impl DnsPacketWrapper {
    pub fn new<T: Into<Vec<u8>>>(buf: T) -> Result<Self, String> {
        let buf = buf.into();
        let slices = get_udp_packet_slices(&buf)?;
        
        let source_ip = match slices.net {
            Some(NetSlice::Ipv4(ref ipv4)) => IpAddr::V4(ipv4.header().source_addr()),
            Some(NetSlice::Ipv6(ref ipv6)) => IpAddr::V6(ipv6.header().source_addr()),
            _ => return Err("Packet is not IP".to_string()),
        };

        let dest_ip = match slices.net {
            Some(NetSlice::Ipv4(ref ipv4)) => IpAddr::V4(ipv4.header().destination_addr()),
            Some(NetSlice::Ipv6(ref ipv6)) => IpAddr::V6(ipv6.header().destination_addr()),
            _ => return Err("Packet is not IP".to_string()),
        };

        let (source_port, dest_port) = match slices.transport {
            Some(TransportSlice::Udp(ref udp)) => (udp.source_port(), udp.destination_port()),
            _ => return Err("Packet is not UDP".to_string()),
        };

        let udp_payload = udp_payload_from_slices(&slices)?.to_vec();

        Ok(Self { source_ip, dest_ip, source_port, dest_port, udp_payload })
    }

    pub fn udp_payload(&self) -> &[u8] {
        &self.udp_payload
    }

    pub fn dns_wrapper(&self) -> Result<dns_parser::Packet, String> {
        dns_wrapper_from_payload(&self.udp_payload)
    }

    pub fn source_ip(&self) -> IpAddr {
        self.source_ip
    }

    pub fn dest_ip(&self) -> IpAddr {
        self.dest_ip
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    pub fn dest_port(&self) -> u16 {
        self.dest_port
    }
}
