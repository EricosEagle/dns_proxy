use std::fs;
use std::net::SocketAddrV4;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub remote_dns_address: SocketAddrV4,
    pub hosts_blacklist: Vec<String>,
}

pub fn read_config(path: &str) -> Config {
    let config_contents = fs::read_to_string(path).expect("Failed to read config contents");
    serde_json::from_str(config_contents.as_str()).expect("Failed to parse config")
}
