use std::fs;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct InjectConfig {
    pub qname_whitelist: Vec<String>,
    pub response_address: IpAddr,
    pub response_ttl: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DnsConfig {
    pub dns_port: u16,
    pub qname_blacklist: Vec<String>,
    pub dns_proxy_address: SocketAddr,
    pub inject: InjectConfig,
}

pub fn read_config(path: &str) -> DnsConfig {
    let config_contents = fs::read_to_string(path).expect("Failed to read config contents");
    serde_json::from_str(config_contents.as_str()).expect("Failed to parse config")
}
