use dns_redirection::dns as dns_proxy;
use dns_redirection::http_server;
use std::thread;

fn main() {
    env_logger::init();
    let mut handles = Vec::new();
    handles.push(thread::spawn(|| {
        dns_proxy::main();
    }));

    handles.push(thread::spawn(|| {
        http_server::main().expect("HTTP Server Error");
    }));

    for handle in handles {
        handle.join().expect("Failed to join thread");
    }
}
