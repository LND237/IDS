pub mod ddos_scanner{
    use std::collections::HashMap;
    use tokio::runtime::Runtime;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::server::server::Server;
    use crate::sniffer::sniffer::{SinglePacket, extract_ip_src_from_packet};

    pub const ATTACK_NAME : &str = "DDOS";
    const RATE_LIMIT: i32 = 500;

    #[derive(Clone)]
    pub struct DdosScanner{
        base: Scanner
    }

    impl DdosScanner{
        ///Constructor of DdosScanner struct.
        /// Input: an IP struct- the IP to check.
        /// Output: a struct of DdosScanner.
        pub fn new(ip: IP) -> Self{
            return DdosScanner{base: Scanner::new(ip, String::from(ATTACK_NAME))};
        }
        ///The function checks the packets which was sniffed before
        /// and decides if there was a Ddos Attack or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> Option<IP> {
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
                if value > RATE_LIMIT{
                    println!("{}: {}", key.copy().get_ip(), value);
                    return Some(key.copy());
                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for DdosScanner{
        ///The function scans and checks if there is
        /// a DDOS Attack or not and handles the result.
        /// Input: self reference(DdosScanner) and a Vec<SinglePacket>
        /// variable- the packets to check.
        /// Output: None
        fn scan(&self, packets: Vec<SinglePacket>){
            let result = DdosScanner::check_packets(packets);

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

}