use dns_proxy::config::{read_config, Config};

use std::net::SocketAddrV4;
use std::net::UdpSocket;

const CONFIG_PATH: &str = "config.json";
const MAX_PACKET_SIZE: usize = 65535;

const TEST_PACKET: &[u8] = &[
    0x20, 0xb0, 0x1, 0xcf, 0x4e, 0x80, 0x4, 0x7c, 0x16, 0xed, 0x9, 0x35, 0x86, 0xdd, 0x60, 0x5,
    0x5, 0x90, 0x0, 0x31, 0x11, 0x40, 0x2a, 0xd, 0x6f, 0xc2, 0x47, 0x30, 0x26, 0x0, 0x76, 0x1d,
    0x26, 0xfb, 0xfd, 0x6, 0x89, 0x25, 0x2a, 0xd, 0x6f, 0xc2, 0x47, 0x30, 0x26, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x1, 0xe4, 0x19, 0x0, 0x35, 0x0, 0x31, 0x1d, 0x85, 0x75, 0x3b, 0x1, 0x0,
    0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x8, 0x64, 0x69, 0x76, 0x65, 0x72, 0x74, 0x6d,
    0x65, // Name: 0x8, 0x64 ... 0x6d, 0x0
    0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x29, 0x5, 0xac, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0,
];

fn hosts_in_blacklist(hosts_blacklist: &[String], questions: &[dns_parser::Question]) -> bool {
    for question in questions {
        let host = &question.qname.to_string();
        if hosts_blacklist
            .iter()
            .any(|blacklisted_host| blacklisted_host == host)
        {
            return true;
        }
    }
    false
}

// Since the wrapper hasn't implemented WinDivertHelperParsePacket
// it is easier to parse the packet ourselves
fn get_udp_payload(buf: &[u8]) -> Option<&[u8]> {
    let Ok(slices) = etherparse::SlicedPacket::from_ethernet(buf) else {
        return None;
    };

    let etherparse::TransportSlice::Udp(udp_layer) = slices.transport? else {
        return None;
    };

    Some(udp_layer.payload())
}

fn parse_dns<'a>() -> Option<(bool, &'a [u8])> {
    let cfg: Config = read_config(CONFIG_PATH);

    let dns_data = get_udp_payload(TEST_PACKET).expect("Packet was not UDP");
    log::debug!("{:?}", dns_data);

    let dns_packet = dns_parser::Packet::parse(dns_data).expect("Failed to parse dns packet");

    Some((
        hosts_in_blacklist(&cfg.hosts_blacklist, &dns_packet.questions),
        dns_data,
    ))
}

fn send_dns_query(
    dest_address: SocketAddrV4,
    query: &[u8],
) -> std::io::Result<([u8; MAX_PACKET_SIZE], usize)> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    log::debug!("{:?}", socket);
    socket.connect(dest_address)?;
    socket.send(query)?;

    let mut reply_buf = [0u8; MAX_PACKET_SIZE];
    let len = socket.recv(&mut reply_buf)?;

    log::debug!(
        "Parsed Reply: {:?}",
        dns_parser::Packet::parse(&reply_buf[..len])
    );

    Ok((reply_buf, len))
}

fn main() {
    env_logger::init();
    let config = read_config(CONFIG_PATH);
    let (blacklisted, dns_data) = parse_dns().unwrap();
    if !blacklisted {
        return;
    };

    let (response, len) = send_dns_query(config.remote_dns_address, dns_data).unwrap();
    let response = &response[..len];

    log::debug!("Reply: {:?}", &response);
}
