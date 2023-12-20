pub mod dns_scanner{
    use std::future::Future;
    use trust_dns_resolver::{TokioAsyncResolver};
    use dns_parser::{Packet, QueryType, RData};
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::error::ResolveError;
    use trust_dns_resolver::lookup_ip::LookupIp;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, SinglePacket, extract_ip_src_from_packet};

    pub const ATTACK_NAME : &str = "DNS";
    pub const DNS_PORT: u16 = 53;
    pub const AMOUNT_PACKETS_SNIFF: i32 = 1;
    pub const TIME_SNIFF: i32 = 5;

    pub struct DnsScanner{
        base: Scanner
    }

    impl ScannerFunctions for DnsScanner{
        fn new(ip: IP) -> Self {
            return Self{base: Scanner::new(ip.copy(), ATTACK_NAME.to_string())};
        }

        fn scan(&self) -> IP {
            let mut sniffer = Sniffer::new(self.base.get_ip(), DNS_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            return DnsScanner::check_packets(packets);
        }

        fn check_packets(packets: Vec<SinglePacket>) -> IP {
            //Going over the packets of the dns
            for packet in packets{
                // Parse the DNS response packet
                let parsed_packet = match Packet::parse(&packet) {
                    Ok(packet) => {
                        packet
                    }
                    Err(_) => {
                        continue; //probably not a DNS Packet
                    }
                };

                let domain_to_check = match extract_domain_from_dns_response(&packet){
                    None => continue, //no domain to compare to
                    Some(domain) => domain
                };

                // Iterate over the answers in the DNS response
                for ip_domain in parsed_packet.answers {
                    let the_given_ip = match ip_domain.data{
                        RData::A(ip_record) => {
                            // Handle the ip address
                            IP::new(ip_record.0.to_string()).unwrap()
                        }
                        _ => continue
                    };
                    let records = send_lookup_request(domain_to_check.clone());

                    for record in records{
                        if record == domain_to_check{
                            continue;
                        }
                    }
                    if !records.is_empty(){ //this site exists but the ip is wrong
                        return extract_ip_src_from_packet(packet);
                    }

                }
            }
            return IP::new_default();
        }
    }
    fn send_lookup_request(domain_to_check: String) -> Vec<String>{
        // Create a resolver with DNSSEC validation enabled
        let dns_resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            .expect("Failed to create resolver");
        let result_dns_resolver = match dns_resolver.lookup_ip(domain_to_check).await{
            Ok(result) => result,
            (_) => return Vec::new()
        };

        let ptr_records: Vec<String> = result_dns_resolver
            .iter()
            .filter(|answer| answer.qtype == QueryType::PTR)
            .filter_map(|answer| {
                if let Some(domain) = answer.data.to_string().strip_suffix('.') {
                    Some(domain.to_string())
                } else {
                    None
                }
            })
            .collect();

        return ptr_records;
    }
    fn extract_domain_from_dns_response(response: &[u8]) -> Option<String> {
        // Parse the DNS response
        let packet = match Packet::parse(response) {
            Ok(packet) => packet,
            Err(_) => return None,
        };

        // Extract the first question from the DNS packet
        let question = match packet.questions.get(0) {
            Some(question) => question,
            None => return None,
        };

        // Check if the question type is A or AAAA (IPv4 or IPv6)
        if question.qtype != QueryType::A && question.qtype != QueryType::AAAA {
            return None;
        }

        // Extract the requested domain
        let domain = question.qname.to_string();

        Some(domain)
    }
}