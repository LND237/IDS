pub mod download_scanner{
    use std::collections::HashSet;
    use std::net::IpAddr;
    use dns_lookup::lookup_addr;
    use tokio::runtime::Runtime;
    use crate::ip::ip::IP;
    use crate::env_file::env_file::get_api_key;
    use crate::scanner::scanner::{run_async_function, Scanner, ScannerFunctions};
    use crate::sniffer::sniffer::{extract_ip_src_from_packet, filter_packets, SinglePacket};
    use crate::xss_scanner::xss_scanner::HTTP_PORT;
    use virustotal3::LastAnalysisStats;
    use virustotal3::VtClient;
    use crate::address::address::Address;
    use crate::server::server::{Server};

    //Public Constants
    pub const ATTACK_NAME : &str = "Drive By Download";
    pub const HTTPS_PORT: u16 = 443;
    const MAX_BAD_SCANS_AMOUNT: i32 = 3;

    static mut CLEAN_IPS: Vec<IP> = Vec::new();

    #[derive(Clone)]
    pub struct DownloadScanner{
        base: Scanner
    }

    impl DownloadScanner {
        //Public function
        ///Constructor of DownloadScanner struct.
        /// Input: an IP variable- the ip to scan.
        /// Output: a struct of DownloadScanner.
        pub fn new(ip: IP) -> Self{
            return Self{base: Scanner::new(ip.clone(), ATTACK_NAME.to_string())};
        }
        //Private Function
        ///The function checks the packets which was sniffed before
        /// and decides if there is a risk for a Drive By Download or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP value- the IP who might do the attack(if
        /// there is no attack-returning default IP Broadcast).
        fn check_packets(packets : Vec<SinglePacket>) -> Option<IP>{
            let src_ips = get_all_src_ips(packets.clone());

            for ip_src in src_ips{
                let mut total_bad_scans = 0;
                unsafe {
                    if CLEAN_IPS.contains(&ip_src){ //this ip was already checked
                        continue;
                    }
                }

                //Sending the ip to the VirusTotal
                match run_async_function(get_results_of_ip(ip_src.copy())){
                    None => {}
                    Some(result) => {total_bad_scans += result.malicious + result.suspicious}
                };
                if total_bad_scans > MAX_BAD_SCANS_AMOUNT as u32 {
                    return Some(ip_src.copy());
                }

                //Extracting the source domain of the packet
                let domain_src = match get_domain(ip_src.copy()){
                    Some(domain) => {domain},
                    None => {continue} //can not find the domain of src ip
                };

                //Sending the domain to VirusTotal
                let domain_result = match run_async_function(get_results_of_domain(domain_src.clone())){
                    Some(res) => {res},
                    None => {continue;} //can not send request to check
                };

                total_bad_scans = domain_result.suspicious + domain_result.malicious;

                if total_bad_scans > MAX_BAD_SCANS_AMOUNT as u32{
                    return Some(ip_src.copy());
                }
                else{
                    unsafe{
                        CLEAN_IPS.push(ip_src.copy()); //this ip was checked and clean
                    }
                }
            }

            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for DownloadScanner{
        /// The function scans the network and checks if there is
        /// a Drive By Download Attack or not and handles the result.
        /// Input: self reference(DownloadScanner), a Vec<SinglePacket> value-
        /// the packets to check and an Address variable- the address
        /// of the client.
        /// Output: None.
        fn scan(&self, packets: Vec<SinglePacket>, client_address: Address) {
            let mut the_packets = filter_packets(packets.clone(), HTTP_PORT);
            the_packets.append(&mut filter_packets(packets.clone(), HTTPS_PORT));
            let result = DownloadScanner::check_packets(the_packets.clone());
            
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

    //Private Static Functions
    ///The function find the domain of the given ip.
    /// Input: an IP variable- the ip to find its ip.
    /// Output: a String value- the domain(if there is an
    /// error- returning None).
    fn get_domain(ip : IP) -> Option<String>{
        let ip_address: IpAddr = ip.get_ip().parse().unwrap();
        return match lookup_addr(&ip_address) {
            Ok(domain) => { Some(domain) }
            Err(_) => { None }
        };
    }

    /// The function extracts all the src ips from the
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

    ///The function sends the domain to virus total async and
    /// gets its results.
    /// Input: a String variable -the domain to check.
    /// Output: an Option<LastAnalysisStats> value- the results(if
    /// exist).
    async fn get_results_of_domain(domain: String) -> Option<LastAnalysisStats> {

        // Example source IP address
        let the_domain: &str = domain.as_str();
        let api_key = &get_api_key();

        // Create a VirusTotal client
        let client = VtClient::new(api_key);

        // Request the domain report
        let report =  match client.report_domain(the_domain.clone()).await{
            Ok(result) => {result}
            Err(_) => { return None}
        };

        return report.data.attributes.last_analysis_stats;
    }

    /// The function sends the IP to virus total async and
    /// gets its results.
    /// Input: an IP variable -the ip to check.
    /// Output: an Option<LastAnalysisStats> value- the results(if
    /// exist).
    async fn get_results_of_ip(ip: IP) -> Option<LastAnalysisStats> {

        let ip_str = ip.copy().get_ip();
        let the_ip: &str = ip_str.as_str();
        let api_key = &get_api_key();

        // Create a VirusTotal client
        let client = VtClient::new(api_key);

        // Request the domain report
        let report =  match client.report_ip_address(the_ip.clone()).await{
            Ok(result) => {result}
            Err(_) => { return None}
        };

        return report.data.attributes.last_analysis_stats;
    }
}

