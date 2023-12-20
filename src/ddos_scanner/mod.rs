pub mod ddos_scanner{
    use std::collections::HashMap;
    use pnet::packet::{Packet, ethernet::EthernetPacket, ipv4::Ipv4Packet};
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, ALL_PORTS, SinglePacket, extract_ip_src_from_packet};

    pub const ATTACK_NAME : &str = "DDOS";
    pub const DDOS_PORT: u16 = ALL_PORTS;
    const AMOUNT_PACKETS_SNIFF: i32 = 100000;
    const TIME_SNIFF: i32 = 5;
    const RATE_LIMIT: i32 = 20000;

    pub struct DdosScanner{
        base: Scanner
    }

    impl ScannerFunctions for DdosScanner{
        ///Constructor of DdosScanner struct.
        /// Input: an IP struct- the IP to check.
        /// Output: an struct of DdosScanner.
        fn new(ip: IP) -> Self{
            return DdosScanner{base: Scanner::new(ip, String::from(ATTACK_NAME))};
        }
        ///The function scans the network and checks if there is
        /// a DDOS Attack or not.
        /// Input: self reference(DdosScanner)
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast).
        fn scan(&self) -> IP{
            let mut sniffer = Sniffer::new(self.base.get_ip(), DDOS_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            return DdosScanner::check_packets(packets);
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was a Ddos Attack or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> IP {
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
                    return key.copy();
                }
            }
            return IP::new_default();
        }

    }

}