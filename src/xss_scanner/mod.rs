pub mod xss_scanner{
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{SinglePacket, extract_ip_src_from_packet, extract_http_payload, filter_packets};

    pub const ATTACK_NAME : &str = "XSS";
    pub const HTTP_PORT: u16 = 80;
    pub const CSP: &str = "Content-Security-Policy";

    #[derive(Clone)]
    pub struct XssScanner{
        base: Scanner
    }

    impl XssScanner{
        ///Constructor of struct XssScanner.
        /// Input: an IP variable-the ip to scan from.
        pub fn new(ip: IP) -> Self {
            return Self{base: Scanner::new(ip.copy(), ATTACK_NAME.to_string())};
        }

        ///The function checks the packets which were sniffed before
        /// and decides if there was a XSS Attack or not.
        /// Input: A vector of SinglePackets - the packets to check.
        /// Output: An IP Value-the IP who did the attack (if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> Option<IP> {
            println!("Amount XSS Packets: {}", packets.clone().len());
            //Going over the packets of the dns
            for mut packet in packets{
                // Parse the HTTP response packet
                let mut payload = match extract_http_payload(&mut packet){
                    Some(the_payload) => {the_payload},
                    None => {continue}
                };
                let headers = match parse_http_headers(&mut payload){
                    Ok(the_headers) => {the_headers},
                    Err(e) => {
                        println!("Err http parse: {}", e.to_string());
                        continue}
                };
                if let None = headers.find(CSP){
                    return Some(extract_ip_src_from_packet(packet));
                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for XssScanner{

        ///The function scans the network and checks if there is
        /// a XSS Attack or not.
        /// Input: self-reference(XssScanner)
        /// Output: An IP Value-the IP of the fake site (if
        /// the site is good-returning default IP Broadcast).
        fn scan(&self, packets: Vec<SinglePacket>) -> Option<IP> {
            return XssScanner::check_packets(filter_packets(packets, HTTP_PORT));
        }

        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
        }
    }


    ///The function extracts the headers from a HTTP packet, if it is not it will return Err
    /// Input: a SinglePacket reference-the response to extract from.
    /// Output: an Option<Vec<Header>> value - the headers of the HTTP packet, or Err if not an HTTP packet
    fn parse_http_headers(payload: &mut SinglePacket) -> Result<String, String> {
        // Assuming the payload is valid UTF-8
        let payload_str = std::str::from_utf8(payload).unwrap_or("Can not show payload");
        // Find the empty line separating headers and body
        if let Some(header_end_index) = payload_str.find("\r\n\r\n") {
            let headers_str = &payload_str[..header_end_index + 4]; // Include the empty line
            return Ok(headers_str.to_string());
        }
        println!("Payloud str: {}", payload_str);
        return Err("could not find end headers".to_string());

    }

}