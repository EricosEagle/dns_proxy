use dns_redirection::dns as dns_proxy;
use std::thread;

fn main() {
    let mut handles = Vec::new();
    handles.push(thread::spawn(|| {
        dns_proxy::main();
    }));

    for handle in handles {
        handle.join().expect("Failed to join thread");
    }
}
