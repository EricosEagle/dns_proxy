use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug)]
pub struct PacketWrapper {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    udp_payload: Vec<u8>,
}

// Since the wrapper hasn't implemented WinDivertHelperParsePacket
// it is easier to parse the packet ourselves
fn get_udp_packet_slices(buf: &[u8]) -> Result<SlicedPacket<'_>, String> {
    let slices = match SlicedPacket::from_ip(buf) {
        Ok(slices) => slices,
        Err(e) => {
            return Err(format!("Failed to parse packet: {}", e));
        }
    };

    if !matches!(
        slices.net,
        Some(NetSlice::Ipv4(_)) | Some(NetSlice::Ipv6(_))
    ) || !matches!(slices.transport, Some(TransportSlice::Udp(_)))
    {
        return Err("Packet is not IPv4/IPv6 or UDP".to_string());
    }

    Ok(slices)
}

fn dns_packet_from_payload(payload: &[u8]) -> Result<simple_dns::Packet, String> {
    simple_dns::Packet::parse(payload).map_err(|e| e.to_string())
}

fn udp_payload_from_slices<'a>(slices: &SlicedPacket<'a>) -> Result<&'a [u8], String> {
    match slices.transport {
        Some(TransportSlice::Udp(ref udp)) => Ok(udp.payload()),
        _ => Err("Packet is not UDP".to_string()),
    }
}

#[allow(dead_code)]
impl PacketWrapper {
    pub fn new<T: AsRef<[u8]>>(buf: T) -> Result<Self, String> {
        let buf = buf.as_ref();
        let slices = get_udp_packet_slices(buf)?;

        let (src_ip, dst_ip, ttl) = match slices.net {
            Some(NetSlice::Ipv4(ref ipv4)) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
                ipv4.header().ttl(),
            ),
            Some(NetSlice::Ipv6(ref ipv6)) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr()),
                ipv6.header().hop_limit(),
            ),
            _ => return Err("Packet is not IP".to_string()),
        };

        let (src_port, dst_port) = match slices.transport {
            Some(TransportSlice::Udp(ref udp)) => (udp.source_port(), udp.destination_port()),
            _ => return Err("Packet is not UDP".to_string()),
        };

        let udp_payload = udp_payload_from_slices(&slices)?.to_vec();

        Ok(Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ttl,
            udp_payload,
        })
    }

    pub fn swap_addresses(&mut self) -> &mut Self {
        (self.src_ip, self.dst_ip) = (self.dst_ip, self.src_ip);
        (self.src_port, self.dst_port) = (self.dst_port, self.src_port);

        self
    }

    pub fn with_src(&self, src_ip: IpAddr, src_port: u16) -> Result<Self, &str> {
        if !matches!(
            (self.src_ip, src_ip),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        ) {
            return Err("Different IP Protocol");
        }

        Ok(Self {
            src_ip,
            dst_ip: self.dst_ip,
            src_port,
            dst_port: self.dst_port,
            ttl: self.ttl,
            udp_payload: self.udp_payload.clone(),
        })
    }

    pub fn with_src_addr(&self, addr: SocketAddr) -> Result<Self, &str> {
        self.with_src(addr.ip(), addr.port())
    }

    pub fn with_dst(&self, dst_ip: IpAddr, dst_port: u16) -> Result<Self, &str> {
        if !matches!(
            (self.dst_ip, dst_ip),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        ) {
            return Err("Different IP Protocol");
        }

        Ok(Self {
            src_ip: self.src_ip,
            dst_ip,
            src_port: self.src_port,
            dst_port,
            ttl: self.ttl,
            udp_payload: self.udp_payload.clone(),
        })
    }

    pub fn with_dst_addr(&self, addr: SocketAddr) -> Result<Self, &str> {
        self.with_dst(addr.ip(), addr.port())
    }

    pub fn with_payload<T: Into<Vec<u8>>>(&self, payload: T) -> Self {
        Self {
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            ttl: self.ttl,
            udp_payload: payload.into(),
        }
    }

    pub fn with_swapped_addresses(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            ttl: self.ttl,
            udp_payload: self.udp_payload.clone(),
        }
    }

    pub fn udp_payload(&self) -> &[u8] {
        &self.udp_payload
    }

    pub fn set_udp_payload(&mut self, udp_payload: Vec<u8>) -> &mut Self {
        self.udp_payload = udp_payload;
        self
    }

    pub fn dns_wrapper(&self) -> Result<simple_dns::Packet, String> {
        dns_packet_from_payload(&self.udp_payload)
    }

    pub fn src_ip(&self) -> IpAddr {
        self.src_ip
    }

    pub fn dst_ip(&self) -> IpAddr {
        self.dst_ip
    }

    pub fn src(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip, self.src_port)
    }

    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    pub fn dst(&self) -> SocketAddr {
        SocketAddr::new(self.dst_ip, self.dst_port)
    }

    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    pub fn to_packet(&self) -> Result<Vec<u8>, String> {
        // Build the response packet with swapped source and destination addresses
        let response = match (self.src_ip, self.dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                PacketBuilder::ipv4(src.octets(), dst.octets(), self.ttl)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                PacketBuilder::ipv6(src.octets(), dst.octets(), self.ttl)
            }
            _ => unreachable!(),
        }
        .udp(self.src_port, self.dst_port);

        let mut result = Vec::<u8>::with_capacity(response.size(self.udp_payload.len()));
        response
            .write(&mut result, &self.udp_payload)
            .map_err(|e| e.to_string())?;

        Ok(result)
    }
}
