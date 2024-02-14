pub mod dns_scanner{
    use dns_parser::{Packet, QueryType, RData};
    use trust_dns_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, SinglePacket};

    pub const ATTACK_NAME : &str = "DNS";
    pub const DNS_PORT: u16 = 53;
    pub const AMOUNT_PACKETS_SNIFF: i32 = 1;
    pub const TIME_SNIFF: i32 = 5;

    #[derive(Clone)]
    pub struct DnsScanner{
        base: Scanner
    }

    impl DnsScanner{
        ///Constructor of struct DnsScanner.
        /// Input: an IP variable- the ip to scan from.
        pub fn new(ip: IP) -> Self {
            return Self{base: Scanner::new(ip.copy(), ATTACK_NAME.to_string())};
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was a Dns Hijacking Attack or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> Option<IP> {
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

                //Extracting the domain to check from the dns response
                let domain_to_check = match extract_domain_from_dns_response(&packet){
                    None => continue, //no domain to compare to
                    Some(domain) => domain
                };

                let records = send_lookup_request(domain_to_check.clone());

                // Iterate over the answers in the DNS response
                for answer_ip in parsed_packet.answers {
                    //Getting the current ip
                    let the_current_ip = match answer_ip.data{
                        RData::A(ip_record) => {
                            // Handle the ip address
                            IP::new(ip_record.0.to_string()).unwrap()
                        }
                        _ => continue
                    };

                    //Going over the given records from the DNSSEC
                    for record in &records{
                        //If the record ip is the given ip
                        if record.get_ip() == the_current_ip.get_ip(){
                            continue;
                        }
                    }
                    if !records.is_empty(){ //this site exists but the ip is wrong
                        //getting the ip of the fake site to block
                        return Some(the_current_ip.copy());
                    }

                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for DnsScanner{

        ///The function scans the network and checks if there is
        /// a DNS HIJACKING Attack or not.
        /// Input: self reference(DnsScanner)
        /// Output: An IP Value- the IP of the fake site(if
        /// the site is good -returning default IP Broadcast).
        fn scan(&self) -> Option<IP> {
            let mut sniffer = Sniffer::new(self.base.get_ip(), DNS_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            return DnsScanner::check_packets(packets);
        }
        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
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
    fn extract_domain_from_dns_response(response: &SinglePacket) -> Option<String> {
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

        return Some(domain);
    }
}