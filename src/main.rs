use dns_proxy::config::{read_config, Config};
use dns_proxy::packet_wrapper::DnsPacketWrapper;
use dns_proxy::windivert_packet::create_windivert_packet_from;
use windivert::layer::NetworkLayer;
use windivert::prelude::{WinDivertFlags, WinDivertPacket};
use windivert::WinDivert;

use std::net::SocketAddrV4;
use std::task::Poll;

use etherparse::{NetSlice, PacketBuilder, TransportSlice};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const CONFIG_PATH: &str = "config.json";
const PACKET_FILTER_TEMPLATE: &str = "(outbound or loopback) and (ip or ipv6) and udp.DstPort == 53 and udp.PayloadLength > {DNS_HEADER_SIZE} and ip.DstAddr != {remote_dns_server}";
const DEFAULT_WINDIVERT_PRIORITY: i16 = 5000; // Arbitrary value
const DNS_HEADER_SIZE: usize = 12;
const MAX_PACKET_SIZE: usize = 65535;
const MAX_CONCURRENT_TASKS: usize = 100; // Arbitrary value

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

    log::trace!("DNS Reply: {:?}", &reply_buf[..len]);

    Ok(reply_buf[..len].to_vec())
}

fn build_injected_packet(packet_data: &[u8], server_reply: Vec<u8>) -> Result<Vec<u8>, String> {
    let slices = etherparse::SlicedPacket::from_ip(packet_data).map_err(|e| e.to_string())?;

    let TransportSlice::Udp(udp) = slices.transport.expect("No transport layer") else {
        return Err("Not UDP packet".to_string());
    };

    // Build the response packet with swapped source and destination addresses
    let response = match slices.net {
        Some(NetSlice::Ipv4(ipv4)) => PacketBuilder::ipv4(
            ipv4.header().destination(),
            ipv4.header().source(),
            ipv4.header().ttl(),
        ),
        Some(NetSlice::Ipv6(ipv6)) => PacketBuilder::ipv6(
            ipv6.header().destination(),
            ipv6.header().source(),
            ipv6.header().hop_limit(),
        ),
        _ => return Err("Not IP packet".to_string()),
    }
    .udp(udp.destination_port(), udp.source_port());

    let mut result = Vec::<u8>::with_capacity(response.size(server_reply.len()));
    response
        .write(&mut result, &server_reply)
        .map_err(|e| e.to_string())?;

    log::trace!("Built injected packet: {:?}", result);

    Ok(result)
}

async fn relay_to_server(
    remote_dns_address: SocketAddrV4,
    request_wrapper: DnsPacketWrapper,
    request_packet: &WinDivertPacket<'static, NetworkLayer>,
) -> Result<WinDivertPacket<'static, NetworkLayer>, String> {
    let payload = request_wrapper.udp_payload();

    let reply = match send_dns_query(remote_dns_address, payload).await {
        Ok(reply) => reply,
        Err(e) => {
            return Err(format!("Failed to send query: {}", e));
        }
    };

    let inject_packet_data = match build_injected_packet(&request_packet.data, reply) {
        Ok(packet) => packet,
        Err(e) => {
            return Err(format!("Failed to build injected packet: {}", e));
        }
    };

    create_windivert_packet_from(inject_packet_data, &request_packet, false, true)
        .map_err(|e| format!("Failed to create WindDivertPacket: {}", e))
}

async fn inject_packets(
    windvt: &WinDivert<NetworkLayer>,
    results: Vec<(
        Result<WinDivertPacket<'static, NetworkLayer>, String>,
        WinDivertPacket<'static, NetworkLayer>,
    )>,
) {
    for (result, inject_packet) in results {
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
                match windvt.send(&inject_packet) {
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
        let remote_dns_address = cfg.remote_dns_address;
        log::info!(
            "Relaying packet to the external DNS server, Source port: {}, hosts: {:?}",
            parsed_packet.source_port(),
            &dns_packet.questions
        );

        let tx = tx.clone();
        tokio::spawn(async move {
            let res = relay_to_server(remote_dns_address, parsed_packet, &packet);
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
