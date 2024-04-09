pub mod dns_scanner{
    use dns_parser::{QueryType, RData};
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::Packet;
    use pnet::packet::udp::UdpPacket;
    use tokio::runtime::Runtime;
    use trust_dns_resolver::{TokioAsyncResolver, config::{ResolverConfig, ResolverOpts}};
    use crate::address::address::Address;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::{BROADCAST_IP, IP};
    use crate::server::server::Server;
    use crate::sniffer::sniffer::{SinglePacket, filter_packets};

    pub const ATTACK_NAME : &str = "DNS";
    pub const DNS_PORT: u16 = 53;

    #[derive(Clone)]
    pub struct DnsScanner{
        base: Scanner
    }

    impl DnsScanner{
        ///Constructor of struct DnsScanner.
        /// Input: an Address variable- the address to scan.
        pub fn new(ip: IP) -> Self {
            return Self{base: Scanner::new(ip.clone(), ATTACK_NAME.to_string())};
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was a Dns Hijacking Attack or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> Option<IP> {
            println!("Amount DNS packets: {}", packets.clone().len());
            //Going over the packets of the dns
            for packet in packets{
                let dns_pack = match extract_dns_packet(&packet){
                    Some(pack) => pack,
                    None => {
                        continue;
                    }
                };
                // Parse the DNS response packet
                let parsed_packet = match dns_parser::Packet::parse(&dns_pack) {
                    Ok(packet) => {
                        packet
                    }
                    Err(_) => {
                        continue; //can not parse the packet
                    }
                };
                //Extracting the domain to check from the dns response
                let domain_to_check = match extract_domain_from_dns_response(&parsed_packet){
                    None => continue, //no domain to compare to
                    Some(domain) => domain
                };

                let records = send_lookup_request(domain_to_check.clone());
                let answers = parsed_packet.answers;
                let mut valid_site = false;
                let mut the_current_ip = IP::new_default();

                // Iterate over the answers in the DNS response
                for answer in answers {
                    //Getting the current ip
                    the_current_ip = match answer.data{
                        RData::A(ip_record) => {
                            // Handle the ip address
                            IP::new(ip_record.0.to_string()).unwrap()
                        }
                        _ => continue
                    };
                    if !records.is_empty(){ //this site exists
                        //Going over the given records from the DNSSEC
                        for record in &records{
                            //If the record ip is the given ip
                            if record.get_ip() == the_current_ip.get_ip(){
                                valid_site = true;
                            }
                        }
                    }
                }
                if !valid_site && the_current_ip.get_ip() != BROADCAST_IP{ //the site is not valid and was checked
                    return Some(the_current_ip.copy());
                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for DnsScanner{
        /// The function scans the network and checks if there is
        /// a DNS HIJACKING Attack or not.
        /// Input: self reference(DnsScanner) and a Vec<SinglePacket>-
        /// the packets to scan.
        /// Output: None.
        fn scan(&self, packets: Vec<SinglePacket>, client_address: Address) {
            let result = DnsScanner::check_packets(filter_packets(packets.clone(), DNS_PORT));

            //Running the async function of handling the result
            let rt = Runtime::new().unwrap();
            rt.block_on(Server::handle_result(client_address.clone(), self.base.get_name(), result))
        }
        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.clone();
        }
    }

    ///The function sends a lookup request to DNSSEC validation
    ///for finding the ips of a certain domain.
    ///Input: a String variable- the domain to check.
    ///Output: A vector of IPs- the ips of the given domain.
    fn send_lookup_request(domain_to_check: String) -> Vec<IP>{
        // Create a resolver with DNSSEC validation enabled
        let dns_resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()).unwrap();

        // Pin the future to the heap
        let binding = dns_resolver.clone();
        let result_dns_resolver = Box::pin(binding.ipv4_lookup(domain_to_check));
        let result_lookup = match Runtime::new() {
            Ok(rt) => rt.block_on(result_dns_resolver),
            _ => return Vec::new()
        };

        //Getting the results of the lookup
        let the_results = match result_lookup {
            Ok(result) => {result}
            Err(_) => { //no results of the lookup
                return Vec::new();
            }
        };

        //Going over the ips from the DNSLookup
        let mut ptr_records = Vec::new();
        for result in the_results{
            ptr_records.push(IP::new(result.to_string()).unwrap());
        }

        return ptr_records;
    }

    ///The function extracts the asked domain from
    ///the dns response.
    /// Input: a dns_parser::Packet reference- the response to extract from.
    /// Output: a Some(String) value - the requested domain (if there is
    /// no domain- the function will return None).
    fn extract_domain_from_dns_response(response: &dns_parser::Packet) -> Option<String> {

        // Extract the first question from the DNS packet
        let question = match response.questions.get(0) {
            Some(question) => question,
            None => return None,
        };

        // Check if the question type is A (IPv4)
        if question.qtype != QueryType::A{
            return None;
        }

        // Extract the requested domain
        let domain = question.qname.to_string();

        return Some(domain);
    }

    ///The function extracts the data of a dns packet.
    /// Input: a SinglePacket reference- the reference to the packet.
    /// Output: Some packet if there is a dns payload, and None
    /// if it does not.
    fn extract_dns_packet(packet: &SinglePacket) -> Option<SinglePacket>{
        let ethernet_packet = EthernetPacket::new(packet)?;
        let ip_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
            let udp_packet = UdpPacket::new(ip_packet.payload())?;
            Some(udp_packet.payload().to_vec())
        }
        else {
            None
        }
    }
}