import argparse
from dnslib import DNSRecord, DNSHeader, DNSQuestion, A, RR
from dnslib.server import DNSServer, BaseResolver

# Define a custom resolver
class SimpleResolver(BaseResolver):
    def __init__(self, constant_ip):
        self.constant_ip = constant_ip

    def resolve(self, request, handler):
        # Create a DNS response
        reply = request.reply()

        # Add a record with the constant IP address for all queries
        # Assuming A record type (IPv4 address)
        reply.add_answer(*RR.fromZone(f"{request.q.qname} 60 A {self.constant_ip}"))

        return reply

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Simple DNS Server that returns a constant IP address.")
    parser.add_argument('--ip', type=str, default='192.168.1.100', help="The constant IP address to return.")
    parser.add_argument('--port', type=int, default=53, help="Port to listen on (default is 53).")
    args = parser.parse_args()

    # Set up DNS server with the specified IP and port
    resolver = SimpleResolver(args.ip)
    dns_server = DNSServer(resolver, port=args.port)

    # Run the DNS server
    print(f"DNS Server is running, returning {args.ip} for all queries on port {args.port}...")
    dns_server.start()

if __name__ == "__main__":
    main()
