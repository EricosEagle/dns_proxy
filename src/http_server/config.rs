use std::fs;
use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub listen_address: SocketAddr,
    pub response_data_path: String,
}

pub fn read_config(path: &str) -> Config {
    let config_contents = fs::read_to_string(path).expect("Failed to read config contents");
    serde_json::from_str(config_contents.as_str()).expect("Failed to parse config")
}
