use dns_proxy::config::{read_config, Config};
use dns_proxy::packet_wrapper::DnsPacketWrapper;
use dns_proxy::windivert_packet::create_windivert_packet_from;
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivertFlags, WinDivertPacket};
use windivert::WinDivert;

use std::net::SocketAddrV4;
use std::sync::Arc;

use etherparse::{NetSlice, PacketBuilder, TransportSlice};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const CONFIG_PATH: &str = "config.json";
const PACKET_FILTER_TEMPLATE: &str = "(outbound or loopback) and ip and udp.DstPort == 53 and udp.PayloadLength > {DNS_HEADER_SIZE} and ip.DstAddr != {remote_dns_server}";
const DEFAULT_WINDIVERT_PRIORITY: i16 = 5000; // Arbitrary value
const DNS_HEADER_SIZE: usize = 12;
const MAX_PACKET_SIZE: usize = 65535;

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

async fn send_dns_query(dest_address: SocketAddrV4, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    socket.connect(dest_address).await?;
    socket.send(query).await?;

    let mut reply_buf = [0u8; MAX_PACKET_SIZE];
    let len = socket.recv(&mut reply_buf).await?;

    log::debug!("DNS Reply: {:?}", &reply_buf[..len]);

    Ok(reply_buf[..len].to_vec())
}

fn build_injected_packet(
    request_packet: &DnsPacketWrapper,
    server_reply: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let slices = request_packet.slices()?;

    let NetSlice::Ipv4(net) = slices.net.unwrap() else {
        return Err("Not IPv4 packet".to_string());
    };
    let TransportSlice::Udp(udp) = slices.transport.unwrap() else {
        return Err("Not UDP packet".to_string());
    };

    // Build response packet with swapped addresses
    let response = PacketBuilder::ipv4(
        net.header().destination(),
        net.header().source(),
        std::cmp::max(net.header().ttl() - 3, 1),
    )
    .udp(udp.destination_port(), udp.source_port());

    let mut result = Vec::<u8>::with_capacity(response.size(server_reply.len()));
    response
        .write(&mut result, &server_reply)
        .map_err(|e| e.to_string())?;

    log::debug!("Built injected packet: {:?}", result);

    Ok(result)
}

async fn relay_to_server(
    windvt: Arc<Mutex<WinDivert<NetworkLayer>>>,
    remote_dns_address: SocketAddrV4,
    request_packet: DnsPacketWrapper,
    windivert_packet: WinDivertPacket<'static, NetworkLayer>,
) {
    let payload = match request_packet.udp_payload() {
        Ok(payload) => payload,
        Err(e) => {
            log::error!("Failed to get UDP payload: {}", e);
            return;
        }
    };

    let reply = match send_dns_query(remote_dns_address, payload).await {
        Ok(reply) => reply,
        Err(e) => {
            log::error!("Failed to send query: {}", e);
            return;
        }
    };

    let inject_packet_data = match build_injected_packet(&request_packet, reply) {
        Ok(packet) => packet,
        Err(e) => {
            log::error!("Failed to build injected packet: {}", e);
            return;
        }
    };

    let inject_packet = match create_windivert_packet_from(inject_packet_data, &windivert_packet, false) {
        Ok(packet) => packet,
        Err(e) => {
            log::error!("Failed to create WindDivertPacket: {}", e);
            return;
        }
    };

    let res = {
        let w = windvt.lock().await;
        w.send(&inject_packet)
    };

    match res {
        Ok(_) => log::debug!("Successfully sent packet"),
        Err(e) => log::error!("Failed to send packet: {}", e),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let cfg: Config = read_config(CONFIG_PATH);

    // Can't format with a const template so we replace the placeholders manually
    let packet_filter = PACKET_FILTER_TEMPLATE
        .replace(
            "{remote_dns_server}",
            &cfg.remote_dns_address.ip().to_string(),
        )
        .replace(
            "{remote_dns_port}",
            &cfg.remote_dns_address.port().to_string(),
        )
        .replace("{DNS_HEADER_SIZE}", &DNS_HEADER_SIZE.to_string());
    log::debug!("Packet filter: {}", packet_filter);

    let windvt = match WinDivert::network(
        packet_filter,
        DEFAULT_WINDIVERT_PRIORITY,
        WinDivertFlags::new(),
    ) {
        Ok(windvt) => windvt,
        Err(e) => {
            log::error!("Failed to create WinDivert handle: {}", e);
            return;
        }
    };

    let windvt = Arc::new(Mutex::new(windvt));
    loop {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let packet = match windvt.lock().await.recv(Some(&mut buf)) {
            Ok(packet) => packet,
            Err(e) => {
                log::error!("Failed to receive packet: {}", e);
                continue;
            }
        };

        let packet = packet.into_owned();

        let parsed_packet = DnsPacketWrapper::from(packet.data.to_vec());
        let dns_packet = match parsed_packet.dns_packet() {
            Ok(dns_packet) => dns_packet,
            Err(e) => {
                log::error!("Failed to parse DNS packet: {}", e);
                windvt
                    .lock()
                    .await
                    .send(&packet)
                    .expect("Failed to reinject non-dns packet");
                continue;
            }
        };

        if dns_packet.header.query
            && dns_packet.header.questions > 0
            && !hosts_in_blacklist(&cfg.hosts_blacklist, &dns_packet.questions)
        {
            let wdt_ref = Arc::clone(&windvt);
            let remote_dns_address = cfg.remote_dns_address;
            log::debug!(
                "Relaying packet to the external DNS server, hosts: {:?}",
                &dns_packet.questions
            );

            // TODO: Find a way to reinject original packet on relay_to_server / divert_to_server errors
            tokio::spawn(async move {
                relay_to_server(
                    wdt_ref,
                    remote_dns_address,
                    parsed_packet,
                    packet,
                ).await
            });
            continue;
        }

        // Reinject non-relayed packets
        match windvt.lock().await.send(&packet) {
            Ok(_) => log::debug!("Successfully resent received packet"),
            Err(e) => log::error!("Failed to resend received packet: {}", e),
        }
    }
}
