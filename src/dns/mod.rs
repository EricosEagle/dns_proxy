pub mod config;
mod packet_wrapper;
mod windivert_packet;

use config::{read_config, Config};
use packet_wrapper::PacketWrapper;
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivertFlags, WinDivertPacket};
use windivert::WinDivert;
use windivert_packet::{create_windivert_packet_from, PacketDirection, PacketSource};

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const CONFIG_PATH: &str = "config_dns.json";
const DEFAULT_WINDIVERT_PRIORITY: i16 = 0;
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

async fn send_dns_query(dest_address: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    socket.connect(dest_address).await?;
    socket.send(query).await?;

    let mut reply_buf = [0u8; MAX_PACKET_SIZE];
    let len = socket.recv(&mut reply_buf).await?;

    log::trace!("DNS Reply: {:?}", &reply_buf[..len]);

    Ok(reply_buf[..len].to_vec())
}

async fn relay_to_server(
    remote_dns_address: SocketAddr,
    request_wrapper: PacketWrapper,
    request_packet: &WinDivertPacket<'static, NetworkLayer>,
) -> Result<WinDivertPacket<'static, NetworkLayer>, String> {
    let reply = match send_dns_query(remote_dns_address, request_wrapper.udp_payload()).await {
        Ok(reply) => reply,
        Err(e) => {
            return Err(format!("Failed to send query: {}", e));
        }
    };

    let inject_wrapper = request_wrapper
        .with_payload(reply)
        .swap_addresses()
        .to_owned();

    let inject_packet_data: Vec<u8> = match inject_wrapper.to_packet() {
        Ok(packet) => packet,
        Err(e) => {
            return Err(format!("Failed to build injected packet: {}", e));
        }
    };

    create_windivert_packet_from(
        inject_packet_data,
        request_packet,
        PacketDirection::Inbound,
        PacketSource::Imposter,
    )
    .map_err(|e| e.to_string())
}

/// Constructs a packet filter string for capturing DNS packets based on the following criteria:
/// - The packet is either IPv4 or IPv6.
/// - The packet's destination UDP port matches the original DNS address port.
/// - The packet's destination IP address does not match the remote DNS address IP.
/// - The UDP payload length is greater than the DNS header size.
/// - The third byte of the UDP payload has its most significant bit (0x80) unset, indicating a DNS query (not a response).
///
/// Note: Bitwise operators aren't supported by the windivert filter syntax, so comparison operators are used instead
fn generate_packet_filter(cfg: &Config) -> String {
    format!(
        "(ip or ipv6) and (udp.DstPort == {} && ip.DstAddr != {}) and udp.PayloadLength > {} and udp.Payload[2] < 0x80",
        cfg.original_dns_address.port(),
        cfg.remote_dns_address.ip(),
        DNS_HEADER_SIZE,
    )
}

#[tokio::main]
pub async fn main() {
    let cfg: Config = read_config(CONFIG_PATH); // TODO: Find way to nest all configs in one file
    let packet_filter = generate_packet_filter(&cfg);
    log::trace!("Packet filter: {}", packet_filter);

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

    main_loop(cfg, windvt).await;
}

async fn main_loop(cfg: Config, windvt: WinDivert<NetworkLayer>) {
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

        if let Err(e) = process_packet(&cfg, windvt.clone(), packet).await {
            log::error!("Error processing packet: {}", e);
        }
    }
}

async fn process_packet(
    cfg: &Config,
    windvt: Arc<Mutex<WinDivert<NetworkLayer>>>,
    packet: WinDivertPacket<'static, NetworkLayer>,
) -> Result<(), String> {
    let packet_wrapper = match PacketWrapper::new(&packet.data) {
        Ok(parsed_packet) => parsed_packet,
        Err(e) => {
            log::error!("Failed to parse packet: {}", e);
            windvt
                .lock()
                .await
                .send(&packet)
                .expect("Failed to reinject non-dns packet");
            return Err("Failed to parse packet".to_string());
        }
    };

    let dns_packet = match packet_wrapper.dns_wrapper() {
        Ok(dns_packet) => dns_packet,
        Err(e) => {
            log::error!("Failed to parse DNS packet: {}", e);
            windvt
                .lock()
                .await
                .send(&packet)
                .expect("Failed to reinject non-dns packet");
            return Err("Failed to parse DNS packet".to_string());
        }
    };

    if !hosts_in_blacklist(&cfg.hosts_blacklist, &dns_packet.questions) {
        log::info!(
            "Relaying packet to the external DNS server, Source port: {}, query: {}, hosts: {:?}",
            packet_wrapper.src_port(),
            dns_packet.header.query,
            &dns_packet.questions
        );

        let remote_address = cfg.remote_dns_address;
        tokio::spawn(async move {
            let pkt = match relay_to_server(remote_address, packet_wrapper, &packet).await {
                Ok(pkt) => {
                    if log::log_enabled!(log::Level::Debug) {
                        log::debug!("Relay packet: {:?}", PacketWrapper::new(&pkt.data))
                    }
                    pkt
                }
                Err(e) => {
                    log::error!("Failed to relay packet: {}", e);
                    packet
                }
            };

            match windvt.lock().await.send(&pkt) {
                Ok(_) => log::info!("Successfully relayed packet"),
                Err(e) => log::error!("Failed to send relay packet: {}", e),
            }
        });
        return Ok(());
    }

    // Reinject non-relayed packets
    match windvt.lock().await.send(&packet) {
        Ok(_) => log::debug!("Successfully resent blacklisted packet"),
        Err(e) => log::error!("Failed to resend blacklisted packet: {}", e),
    }

    Ok(())
}
