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
    "original_dns_address": "127.0.0.1:53",
    "remote_dns_address": "8.8.8.8:53",
    "hosts_blacklist": ["example.com", "test.com"],
    "redirect_whitelist": ["whitelist.com"],
    "redirect_address": "192.168.1.1"
}
```

- `original_dns_address`: The original DNS server address.
- `remote_dns_address`: The remote DNS server address to relay queries.
- `hosts_blacklist`: List of hosts to be blacklisted.
- `redirect_whitelist`: List of hosts to be whitelisted for redirection.
- `redirect_address`: The IP address to redirect blacklisted hosts.

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
