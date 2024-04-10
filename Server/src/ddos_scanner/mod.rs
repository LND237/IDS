pub mod ddos_scanner{
    use std::collections::HashMap;
    use tokio::runtime::Runtime;
    use crate::address::address::Address;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::server::server::Server;
    use crate::sniffer::sniffer::{SinglePacket, extract_ip_src_from_packet};

    pub const ATTACK_NAME : &str = "DDOS";
    const RATE_LIMIT: i32 = 750;

    #[derive(Clone)]
    pub struct DdosScanner{
        base: Scanner
    }

    impl DdosScanner{
        ///Constructor of DdosScanner struct.
        /// Input: an IP struct- the address to scan.
        /// Output: a struct of DdosScanner.
        pub fn new(ip: IP) -> Self{
            return DdosScanner{base: Scanner::new(ip.clone(), String::from(ATTACK_NAME))};
        }
        ///The function checks the packets which was sniffed before
        /// and decides if there was a Ddos Attack or not.
        /// Input: A vector of SinglePackets- the packets to check and
        /// an IP value- the ip of the client.
        /// Output: An IP value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>, client_ip: IP) -> Option<IP> {
            let mut hash_map_ip: HashMap<IP, i32> = HashMap::new();

            //Going over the packets
            for packet in packets{
                let ip_src = extract_ip_src_from_packet(packet);
                let former_value;
                match  hash_map_ip.get(&ip_src){ //getting the last value
                    None => former_value = 0,
                    Some(value) => former_value = *value
                }
                let new_val = former_value + 1;
                hash_map_ip.insert(ip_src, new_val);
            }

            //Going over the hashmap
            for (key, value) in hash_map_ip{
                //If this IP did a DDos attack
                if value > RATE_LIMIT && key.get_ip() != client_ip.get_ip(){
                    return Some(key.copy());
                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for DdosScanner{
        ///The function scans and checks if there is
        /// a DDOS Attack or not and handles the result.
        /// Input: self reference(DdosScanner), a Vec<SinglePacket>
        /// variable- the packets to check and an Address variable-
        /// the address of the client.
        /// Output: None
        fn scan(&self, packets: Vec<SinglePacket>, client_address: Address){
            let result = DdosScanner::check_packets(packets, client_address.clone().get_ip());

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

}