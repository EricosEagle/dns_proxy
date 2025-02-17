use dns_proxy::config::{read_config, Config};
use dns_proxy::packet_wrapper::DnsPacketWrapper;
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivertFlags, WinDivertPacket};
use windivert::WinDivert;

use std::borrow::Cow;
use std::sync::Arc;

use tokio::sync::Mutex;

const CONFIG_PATH: &str = "config.json";
const PACKET_FILTER_TEMPLATE: &str = "(ip or ipv6) \
    and ((udp.DstPort == {original_dns_port} && ip.DstAddr != {remote_dns_server}) or (udp.SrcPort == {remote_dns_port} and ip.SrcAddr == {remote_dns_server})) \
    and udp.PayloadLength > {DNS_HEADER_SIZE}";
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

async fn divert_packet(
    cfg: Config,
    request_wrapper: DnsPacketWrapper,
    request_packet: &WinDivertPacket<'static, NetworkLayer>,
) -> Result<WinDivertPacket<'static, NetworkLayer>, String> {
    let mut modified_packet = request_packet.clone();
    let modified_wrapper = if request_packet.address.outbound() {
        request_wrapper.with_dst_addr(cfg.remote_dns_address)
    } else {
        request_wrapper.with_src_addr(cfg.original_dns_address)
    }?;

    let modified_buf: Vec<u8> = modified_wrapper.try_into()?;
    modified_packet.data = Cow::from(modified_buf);

    Ok(modified_packet)
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
        .replace(
            "{original_dns_port}",
            &cfg.original_dns_address.port().to_string(),
        )
        .replace("{DNS_HEADER_SIZE}", &DNS_HEADER_SIZE.to_string());
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
    let parsed_packet = match DnsPacketWrapper::new(packet.data.to_vec()) {
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

    let dns_packet = match parsed_packet.dns_wrapper() {
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
            "Diverting packet to the external DNS server, Source port: {}, query: {}, hosts: {:?}",
            parsed_packet.src_port(),
            dns_packet.header.query,
            &dns_packet.questions
        );

        let cfg = cfg.clone();
        tokio::spawn(async move {
            let pkt = match divert_packet(cfg, parsed_packet, &packet).await {
                Ok(pkt) => {
                    if log::log_enabled!(log::Level::Debug) {
                        log::debug!(
                            "Divert packet: {:?}",
                            DnsPacketWrapper::new(pkt.data.clone())
                        )
                    }
                    pkt
                }
                Err(e) => {
                    log::error!("Failed to divert packet: {}", e);
                    packet
                }
            };

            match windvt.lock().await.send(&pkt) {
                Ok(_) => log::info!("Successfully diverted packet"),
                Err(e) => log::error!("Failed to send diverted packet: {}", e),
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
