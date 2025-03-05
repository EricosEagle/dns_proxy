# DNS Redirection Proxy

A Rust-based DNS proxy using WinDivert and Rust. This project intercepts DNS queries and redirects them based on configurable rules.

## Features

- Intercepts DNS queries using WinDivert.
- Configurable redirection rules.
- Supports blacklisting and whitelisting of hosts.
- Relays DNS queries to a remote DNS server if not blacklisted.
- Provides an HTTP server for configuration management.

## Configuration

The project uses two configuration files:

1. `config_http.json`: Configuration for the HTTP server.
2. `config_dns.json`: Configuration for the DNS proxy.

### `config_http.json`

```json
{
    "listen_address": "127.0.0.1:8080",
    "response_data_path": "path/to/response/data"
}
```

- `listen_address`: The address and port where the HTTP server listens.
- `response_data_path`: The path to the response data file.

### `config_dns.json`

```json
{
    "dns_port": 53,
    "qname_blacklist": ["example.com", "test.com"],
    "dns_proxy_address": "127.0.0.1:53",
    "inject": {
        "qname_whitelist": ["whitelist.com"],
        "response_address": "192.168.1.1",
        "response_ttl": 300
    }
}
```

- `dns_port`: The port which we will listen for DNS requests on.
- `qname_blacklist`: List of hosts to be blacklisted.
- `dns_proxy_address`: The address and port of the DNS server we will forward traffic to.
- `inject.qname_whitelist`: List of hosts to be whitelisted for redirection.
- `inject.response_address`: The IP address to redirect whitelisted hosts.
- `inject.response_ttl`: The TTL for the injected response. (Should be short, so if the whitelist changes programs will revert to using the original IP)

## Usage

### Running all modules

To run all modules together as separate threads:

```sh
cargo run --bin dns_redirection
```

### Running the HTTP Server

To run the HTTP server:

```sh
cargo run --bin http_server
```

### Running the DNS Proxy

To run the DNS proxy:

```sh
cargo run --bin dns_proxy
```

## Dependencies

- [hyper](https://crates.io/crates/hyper): HTTP library.
- [tokio](https://crates.io/crates/tokio): Asynchronous runtime.
- [serde](https://crates.io/crates/serde): Serialization framework.
- [windivert](https://crates.io/crates/windivert): WinDivert bindings for Rust.
- [simple-dns](https://crates.io/crates/simple-dns): DNS packet parser. (Used instead of dns parser as it is still maintained).

## License

This project is licensed under the MIT License.
