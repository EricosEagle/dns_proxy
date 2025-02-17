use dns_proxy::config::{read_config, Config};
use dns_proxy::packet_wrapper::DnsPacketWrapper;
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivertFlags, WinDivertPacket};
use windivert::WinDivert;

use std::borrow::Cow;
use std::task::Poll;

use tokio::sync::mpsc;

const CONFIG_PATH: &str = "config.json";
const PACKET_FILTER_TEMPLATE: &str = "(ip or ipv6) \
    and ((udp.DstPort == {original_dns_port} && ip.DstAddr != {remote_dns_server}) or (udp.SrcPort == {remote_dns_port} and ip.SrcAddr == {remote_dns_server})) \
    and udp.PayloadLength > {DNS_HEADER_SIZE}";
const DEFAULT_WINDIVERT_PRIORITY: i16 = 0;
const DNS_HEADER_SIZE: usize = 12;
const MAX_PACKET_SIZE: usize = 65535;
const MAX_CONCURRENT_TASKS: usize = 256;

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

async fn inject_packets(
    windvt: &WinDivert<NetworkLayer>,
    results: Vec<(
        Result<WinDivertPacket<'static, NetworkLayer>, String>,
        WinDivertPacket<'static, NetworkLayer>,
    )>,
) {
    for (result, request_packet) in results {
        match result {
            Ok(inject_packet) => match windvt.send(&inject_packet) {
                Ok(_) => {
                    log::info!("Successfully sent response packet");
                    if log::log_enabled!(log::Level::Debug) {
                        log::debug!(
                            "Sent packet: {:?}",
                            DnsPacketWrapper::new(inject_packet.data).unwrap()
                        );
                    }
                }
                Err(e) => {
                    log::error!("Failed to send packet: {}", e);
                    continue;
                }
            },
            Err(e) => {
                log::error!("Failed to create inject packet: {}", e);
                match windvt.send(&request_packet) {
                    Ok(_) => {
                        log::debug!("Successfully resent original packet after failure")
                    }
                    Err(e) => {
                        log::error!("Failed to resend original packet after failure: {}", e)
                    }
                }
            }
        }
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

    let (tx, mut rx) = mpsc::channel::<(
        Result<WinDivertPacket<'static, NetworkLayer>, String>,
        WinDivertPacket<'static, NetworkLayer>,
    )>(MAX_CONCURRENT_TASKS);

    let waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);

    main_loop(&cfg, &windvt, &tx, &mut rx, &mut cx).await;
}

async fn main_loop(
    cfg: &Config,
    windvt: &WinDivert<NetworkLayer>,
    tx: &mpsc::Sender<(
        Result<WinDivertPacket<'static, NetworkLayer>, String>,
        WinDivertPacket<'static, NetworkLayer>,
    )>,
    rx: &mut mpsc::Receiver<(
        Result<WinDivertPacket<'static, NetworkLayer>, String>,
        WinDivertPacket<'static, NetworkLayer>,
    )>,
    cx: &mut std::task::Context<'_>,
) {
    loop {
        let mut results: Vec<(
            Result<WinDivertPacket<'static, NetworkLayer>, String>,
            WinDivertPacket<'static, NetworkLayer>,
        )> = Vec::new();
        match rx.poll_recv_many(cx, &mut results, MAX_CONCURRENT_TASKS) {
            Poll::Pending => log::debug!("No packets to inject"),
            Poll::Ready(0) => {
                log::error!("Channel closed, aborting");
                break;
            }
            Poll::Ready(_) => {
                inject_packets(windvt, results).await;
            }
        }

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let packet = match windvt.recv(Some(&mut buf)) {
            Ok(packet) => packet,
            Err(e) => {
                log::error!("Failed to receive packet: {}", e);
                continue;
            }
        };

        let packet = packet.into_owned();

        if let Err(e) = process_packet(cfg, windvt, tx, packet).await {
            log::error!("Error processing packet: {}", e);
        }
    }
}

async fn process_packet(
    cfg: &Config,
    windvt: &WinDivert<NetworkLayer>,
    tx: &mpsc::Sender<(
        Result<WinDivertPacket<'static, NetworkLayer>, String>,
        WinDivertPacket<'static, NetworkLayer>,
    )>,
    packet: WinDivertPacket<'static, NetworkLayer>,
) -> Result<(), String> {
    let parsed_packet = match DnsPacketWrapper::new(packet.data.to_vec()) {
        Ok(parsed_packet) => parsed_packet,
        Err(e) => {
            log::error!("Failed to parse packet: {}", e);
            windvt
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
                .send(&packet)
                .expect("Failed to reinject non-dns packet");
            return Err("Failed to parse DNS packet".to_string());
        }
    };

    if !dns_packet.header.query || dns_packet.header.questions <= 0 {
        log::warn!("Received non-query packet, reinjecting");
        match windvt.send(&packet) {
            Ok(_) => log::debug!("Successfully resent non-query packet"),
            Err(e) => log::error!("Failed to resend non-query packet: {}", e),
        }
        return Ok(());
    }

    if !hosts_in_blacklist(&cfg.hosts_blacklist, &dns_packet.questions) {
        log::info!(
            "Relaying packet to the external DNS server, Source port: {}, hosts: {:?}",
            parsed_packet.src_port(),
            &dns_packet.questions
        );

        let tx = tx.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let res = divert_packet(cfg, parsed_packet, &packet);
            tx.send((res.await, packet))
                .await
                .expect("Failed to send injected packet over channel");
        });
        return Ok(());
    }

    // Reinject non-relayed packets
    match windvt.send(&packet) {
        Ok(_) => log::debug!("Successfully resent blacklisted packet"),
        Err(e) => log::error!("Failed to resend blacklisted packet: {}", e),
    }

    Ok(())
}
