pub mod xss_scanner{
    use pnet::packet::{ethernet::EthernetPacket,
                       ip::IpNextHeaderProtocols,
                       ipv4::Ipv4Packet,
                       Packet,
                       tcp::TcpPacket};
    use tokio::runtime::Runtime;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::server::server::{Server};
    use crate::sniffer::sniffer::{SinglePacket, extract_ip_src_from_packet, filter_packets};

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
                //Extracting the http headers of the packet
                let headers = match parse_http_headers(&mut payload){
                    Ok(the_headers) => {the_headers},
                    Err(_) => {continue}
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
        /// a XSS Attack or not and handles the result.
        /// Input: self-reference(XssScanner) and a Vec<SinglePacket>
        /// variable- the packets to check.
        /// Output: None.
        fn scan(&self, packets: Vec<SinglePacket>) {
            let result = XssScanner::check_packets(filter_packets(packets.clone(), HTTP_PORT));

            //Running the async function of handling the result
            let rt = Runtime::new().unwrap();
            rt.block_on(Server::handle_result(self.base.get_ip(), self.base.get_name(), result))
        }

        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
        }
    }


    ///The function extracts the headers from an HTTP packet, if it is not it will return Err
    /// Input: a SinglePacket reference-the response to extract from.
    /// Output: a Result<String, String> value - the headers of the HTTP packet, or Err if fails.
    fn parse_http_headers(payload: &mut SinglePacket) -> Result<String, String> {
        // Assuming the payload is valid UTF-8
        let payload_str = std::str::from_utf8(payload).unwrap_or("Can not show payload");
        // Find the empty line separating headers and body
        if let Some(header_end_index) = payload_str.find("\r\n\r\n") {
            let headers_str = &payload_str[..header_end_index + 4]; // Include the empty line
            return Ok(headers_str.to_string());
        }
        return Err("could not find end headers".to_string());
    }

    ///The function extracts the http payload from
    /// the packet.
    /// Input: a reference to a SinglePacket variable-
    /// the packet to extract the http payload from.
    /// Output: an Option<SinglePacket> value- the payload
    /// if exists.
    pub fn extract_http_payload(packet: &SinglePacket) -> Option<SinglePacket> {
        let ethernet_packet = EthernetPacket::new(packet)?;
        let ip_packet = Ipv4Packet::new(ethernet_packet.payload())?;
        if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
            let tcp_packet = TcpPacket::new(ip_packet.payload())?;
            Some(tcp_packet.payload().to_vec())
        } else {
            None
        }
    }

}