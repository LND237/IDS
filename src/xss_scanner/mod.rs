pub mod xss_scanner{
    use trust_dns_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, SinglePacket};
    use httparse::{Request, Status, EMPTY_HEADER, Header};
    use std::io::Cursor;
    use pnet::packet::Packet;


    pub const ATTACK_NAME : &str = "XSS";
    pub const DNS_PORT: u16 = 80;
    pub const AMOUNT_PACKETS_SNIFF: i32 = 1;
    pub const TIME_SNIFF: i32 = 5;

    pub struct XssScanner{
        base: Scanner
    }

    impl XssScanner{
        ///Constructor of struct XssScanner.
        /// Input: an IP variable- the ip to scan from.
        pub fn new(ip: IP) -> Self {
            return Self{base: Scanner::new(ip.copy(), ATTACK_NAME.to_string())};
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was a Dns Hijacking Attack or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> IP {
            //Going over the packets of the dns
            for packet in packets{
                // Parse the HTTP response packet
                let headers = parse_http_headers(&packet);
                for header in headers {
                    if header.name().eq_ignore_ascii_case("Content-Security-Policy") {
                        println!("CSP header found:");
                        // Process the CSP value as needed
                        break; // Exit the loop if you only need to check for presence
                    }
                }
            }
            return IP::new_default();
        }
    }

    impl ScannerFunctions for XssScanner{

        ///The function scans the network and checks if there is
        /// a DNS HIJACKING Attack or not.
        /// Input: self reference(XssScanner)
        /// Output: An IP Value- the IP of the fake site(if
        /// the site is good -returning default IP Broadcast).
        fn scan(&self) -> IP {
            let mut sniffer = Sniffer::new(self.base.get_ip(), DNS_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            return XssScanner::check_packets(packets);
        }
    }

    ///The function sends a lookup request to DNSSEC validation
    ///for finding the ips of a certain domain.
    ///Input: a String variable- the domain to check.
    ///Output: A vector of IPs- the ips of the given domain.
    fn send_lookup_request(domain_to_check: String) -> Vec<IP>{
        // Create a resolver with DNSSEC validation enabled
        let dns_resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            .expect("Failed to create resolver");
        let result_dns_resolver = match futures::executor::block_on(dns_resolver.ipv4_lookup(domain_to_check)){
            Ok(result) => result,
            _ => return Vec::new()
        };

        //Going over the ips from the DNSLookup
        let mut ptr_records = Vec::new();
        for result in result_dns_resolver{
            ptr_records.push(IP::new(result.to_string()).unwrap())
        }

        return ptr_records;
    }

    ///The function extracts the asked domain from
    ///the dns response.
    /// Input: a SinglePacket reference- the response to extract from.
    /// Output: a Some(String) value - the requested domain(if there is
    /// no domain- the function will return None.
    fn parse_http_headers(response: &SinglePacket) -> Option<[Header<'static>; 16]> {
        let mut cursor =  match Cursor::new(&response) {
            Ok(packet) => {
                packet
            }
            Err(_) => {
                return  None; //cursor problem
            }
        };
        let mut headers = [EMPTY_HEADER; 16];
        match httparse::parse_headers(&mut cursor, &mut headers) {  // Pass the headers slice
            Ok(Status::Complete(headers_len)) => {
                // Headers parsed successfully
                let req = Request::new(&mut headers);  // Create the Request object now
                println!("Headers:");
                for header in req.headers {
                    println!("  {}: {:?}", header.name, header.value);
                }

                // Extract request body (if present)
                let body = &response[headers_len..];
                // Process the body as needed
                println!("{:?}",body.payload());
            },
            // Handle other parsing outcomes...
            _ => { return  None}
        }
        return Some(headers)
    }
}