pub mod xss_scanner{
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, SinglePacket, extract_ip_src_from_packet, get_string_packet};
    use httparse::{EMPTY_HEADER, Response, Error, Header};

    pub const ATTACK_NAME : &str = "XSS";
    pub const HTTP_PORT: u16 = 80;
    pub const AMOUNT_PACKETS_SNIFF: i32 = 100;
    pub const TIME_SNIFF: i32 = 5;
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
            let mut csp_found = false;
            //Going over the packets of the dns
            for mut packet in packets{
                // Parse the HTTP response packet
                let headers = parse_http_headers(&mut packet).unwrap();
                for header in headers {
                    if header.name.eq_ignore_ascii_case(CSP){
                        // Process the CSP value as needed
                        csp_found = true;
                        break; // Exit the loop if you only need to check for presence
                    }

                }
                if !csp_found
                {
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
        fn scan(&self) -> Option<IP> {
            let mut sniffer = Sniffer::new(self.base.get_ip(), HTTP_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            return XssScanner::check_packets(packets);
        }

        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
        }
    }


    ///The function extracts the headers from a http packet, if it is not it will throw an error
    /// Input: a SinglePacket reference-the response to extract from.
    /// Output: an Result<Vec<Header>> value - the headers of the HTTP packet, or None if not an HTTP packet
    fn parse_http_headers(response: &mut Vec<u8>) -> Result<Vec<Header>, Error> {
        let mut headers = Vec::new(); // Dynamic header storage
        let mut resp = Response::new(&mut headers);

        match resp.parse(response) {
            Ok(_) => Ok(headers),  // Return headers directly
            Err(e) => Err(e),      // Propagate httparse error
        }
    }
}