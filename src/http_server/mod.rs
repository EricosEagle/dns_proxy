mod config;

use http_body_util::Full;
use hyper::body::Bytes;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::fs;
use tokio::net::TcpListener;
use tokio::task;

const CONFIG_PATH: &str = "config_http.json";

pub fn extract_full_url<T>(req: &Request<T>) -> Result<Bytes, &str> {
    // Get the URI from the request
    let uri = req.uri();

    // Create a BytesMut to build our URL
    let mut url = Vec::new();

    // Add scheme (http/https)
    if let Some(scheme) = uri.scheme() {
        url.extend_from_slice(scheme.as_str().as_bytes());
        url.extend_from_slice(b"://");
    } else {
        // Default to http if scheme is not present
        url.extend_from_slice(b"http://");
    }

    // Add authority (host:port)
    if let Some(authority) = uri.authority() {
        url.extend_from_slice(authority.as_str().as_bytes());
    } else {
        // Try to get host from headers if not in URI  (common in HTTP/1.1)
        let host = req
            .headers()
            .get(hyper::header::HOST)
            .ok_or("Failed to find host")?;
        url.extend_from_slice(host.as_bytes());
    }

    // Add path
    url.extend_from_slice(uri.path().as_bytes());

    // Add query parameters if present
    if let Some(query) = uri.query() {
        url.extend_from_slice(b"?");
        url.extend_from_slice(query.as_bytes());
    }

    // Convert to Bytes and return
    Ok(url.into())
}

async fn proxy_response(
    req: Request<hyper::body::Incoming>,
    inject_payload_path: &str,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let _inject_payload = fs::read(inject_payload_path);
    let full_url = extract_full_url(&req)?;

    // let response: Vec<u8> = todo!("Forward HTTP Request, send response with injected payload");

    // response.extend(inject_payload.await?);
    // let body: Bytes = response.into();
    let response = Response::builder()
        .header("Content-Type", "text/html")
        .body(Full::new(full_url))?;

    Ok(response)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = config::read_config(CONFIG_PATH);

    let listener = TcpListener::bind(cfg.listen_address).await?;
    log::info!("HTTP Server listening on {}", cfg.listen_address);

    loop {
        let (stream, addr) = listener.accept().await?;
        log::info!("Request received: [{} > {}]", addr, cfg.listen_address);
        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        let request_path = cfg.response_data_path.clone();
        task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(|req| proxy_response(req, &request_path)))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
