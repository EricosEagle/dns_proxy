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

async fn const_response(
    _: Request<hyper::body::Incoming>,
    request_path: &str,
) -> Result<Response<Full<Bytes>>, Box<dyn std::error::Error + Send + Sync>> {
    let response_data = fs::read(request_path).await?;
    let body: Bytes = response_data.into();

    let response = Response::builder()
        .header("Content-Type", "text/html")
        .body(Full::new(body))?;

    Ok(response)
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = config::read_config(CONFIG_PATH);

    let listener = TcpListener::bind(cfg.listen_address).await?;

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
                .serve_connection(io, service_fn(|req| const_response(req, &request_path)))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
