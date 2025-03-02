use std::fs;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub original_dns_address: SocketAddr,
    pub remote_dns_address: SocketAddr,
    pub hosts_blacklist: Vec<String>,
    pub inject_response_whitelist: Vec<String>,
    pub redirect_address: IpAddr,
}

pub fn read_config(path: &str) -> Config {
    let config_contents = fs::read_to_string(path).expect("Failed to read config contents");
    serde_json::from_str(config_contents.as_str()).expect("Failed to parse config")
}
