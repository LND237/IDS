pub mod download_scanner{
    use std::collections::HashSet;
    use std::net::IpAddr;
    use dns_lookup::lookup_addr;
    use tokio::runtime::Runtime;
    use crate::ip::ip::IP;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::sniffer::sniffer::{extract_ip_src_from_packet, SinglePacket, Sniffer};
    use crate::xss_scanner::xss_scanner::HTTP_PORT;

    //Public Constants
    pub const ATTACK_NAME : &str = "Drive By Download";
    pub const DOWNLOAD_PORT_1 : u16 = HTTP_PORT;
    pub const HTTPS_PORT: u16 = 443;

    //Private Constants
    const AMOUNT_PACKETS_SNIFF: i32 = 50;
    const TIME_SNIFF: i32 = 3;
    const MAX_MALICIOUS_SCANS_AMOUNT: i32 = 6;

    pub struct DownloadScanner{
        base: Scanner
    }

    impl DownloadScanner {
        //Public function
        ///Constructor of DownloadScanner struct.
        /// Input: an IP struct- the IP to check.
        /// Output: an struct of DownloadScanner.
        pub fn new(ip: IP) -> Self{
            return Self{base: Scanner::new(ip.copy(), ATTACK_NAME.to_string())};
        }
        //Private Function
        ///The function checks the packets which was sniffed before
        /// and decides if there is a risk for a Drive By Download or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP Value- the IP who might do the attack(if
        /// there is no attack-returning default IP Broadcast).
        fn check_packets(packets : Vec<SinglePacket>) -> Option<IP>{
            const MALICIOUS_STR: &str = "malicious";

            let src_ips = get_all_src_ips(packets.clone());

            for ip_src in src_ips{
                //Extracting the source domain of the packet
                let domain_src = match get_domain(ip_src.copy()){
                    Ok(domain) => {domain},
                    Err(_) => {return Some(IP::new_default())} //can not find the domain of src ip
                };

                //Sending the domain to VirusTotal
                let result = match send_domain_to_virus_total(domain_src.clone()){
                    Ok(res) => {res}
                    Err(_) => {return Some(IP::new_default())} //can not send request to check
                };

                //Checking the amount of malicious results
                if result.matches(MALICIOUS_STR).count() >= MAX_MALICIOUS_SCANS_AMOUNT as usize{
                    return Some(ip_src.copy());
                }
            }

            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for DownloadScanner{
        ///The function scans the network and checks if there is
        /// a Drive By Download Attack or not.
        /// Input: self reference(DownloadScanner)
        /// Output: An IP Value- the IP who might do the attack(if
        /// there is no attack-returning default IP Broadcast).
        fn scan(&self) -> Option<IP> {
            let mut sniffer_1 = Sniffer::new(self.base.get_ip(), DOWNLOAD_PORT_1).unwrap();
            let mut sniffer_2 = Sniffer::new(self.base.get_ip(), HTTPS_PORT).unwrap();
            let mut packets = sniffer_1.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            packets.append(&mut sniffer_2.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF));
            return DownloadScanner::check_packets(packets);
        }
    }

    //Private Static Functions
    ///The function find the domain of the given ip.
    /// Input: an IP variable- the ip to find its ip.
    /// Output: a String value- the domain(if there is an
    /// error- returning Err).
    fn get_domain(ip : IP) -> Result<String, String>{
        let ip_address: IpAddr = ip.get_ip().parse().unwrap();
        return match lookup_addr(&ip_address) {
            Ok(domain) => {Ok(domain)}
            Err(_) => {Err("Can not locate sender!".to_string())}
        };
    }

    ///The function sends the domain to check at the
    /// Virus Total site.
    /// Input: a String variable- the domain to check.
    /// Output: a String value- the response of the site(if
    /// there is an error- returning Err).
    fn send_domain_to_virus_total(domain: String) -> Result<String, String> {
        //Constants for Sending the request
        const API_KEY : &str = "cb8ea921f68903f1f192f4db50926e4bef971e95939e10c19da7256ac4ae344b";
        const BASE_URL: &str = "https://www.virustotal.com/api/v3/urls/";

        let rt = Runtime::new().unwrap();

        let url = BASE_URL.to_string() + &String::from(domain.clone().to_string());

        //Sending the request
        let response = match rt.block_on(send_get_request(url.clone(), API_KEY.to_string())) {
            Ok(response) => {response},
            Err(_) => {return Err("Error sending request to virus total".to_string())}
        };

        return Ok(response);
    }

    ///The function sends a get request with an apikey header.
    /// Input: 2 String variables- the url to send the request
    /// to and the apikey for the header.
    /// Output: a String value- the response of the request(if
    /// there is an error- returning Err).
    async fn send_get_request(url : String, apikey: String) -> Result<String, String>{
        let client = reqwest::Client::new();
        let result = client
            .get(&url)
            .header("x-apikey", apikey.clone())
            .send()
            .await
            .map_err(|err| err.to_string())?;

        if result.status().is_success() {
            let text = result.text().await.map_err(|err| err.to_string())?;
            Ok(text)
        } else {
            Err("Request to VirusTotal failed".to_string())
        }
    }

    ///The function extracts all the src ips from the
    /// packets and remove duplicate ones.
    /// Input: a Vector variable of SinglePackets- the
    /// packets to go over.
    /// Output: an HashSet of ips- the set with all the src ips
    /// from the packets.
    fn get_all_src_ips(packets: Vec<SinglePacket>) -> HashSet<IP>{
        let mut set_ips = HashSet::new();

        //Going over the packets
        for packet in packets{
            set_ips.insert(extract_ip_src_from_packet(packet));
        }
        return set_ips;
    }
}