pub mod smurf_scanner{
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::Packet;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{SinglePacket};

    pub const ATTACK_NAME : &str = "Smurf";
    const RATE_LIMIT: i32 = 150;

    #[derive(Clone)]
    pub struct SmurfScanner{
        base: Scanner
    }

    impl SmurfScanner{
        ///Constructor of DdosScanner struct.
        /// Input: an IP struct- the IP to check.
        /// Output: an struct of DdosScanner.
        pub fn new(ip: IP) -> Self{
            return SmurfScanner{base: Scanner::new(ip, String::from(ATTACK_NAME))};
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was a Smurf Attack or not.
        /// Input: A vector of SinglePackets- the packets to check.
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>) -> Option<IP> {
            let mut amount_icmp_packets = 0;
            //Going over the packets
            for packet in packets{
                if is_icmp_packet(packet.clone()){
                    amount_icmp_packets += 1;
                }
            }
            println!("Amount of ICMPs: {}", amount_icmp_packets);
            //Checking if it is over the RATE_LIMIT
            if amount_icmp_packets >= RATE_LIMIT{
                return None;
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for SmurfScanner{
        ///The function scans the network and checks if there is
        /// a Smurf Attack or not.
        /// Input: self reference(DdosScanner)
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast).
        fn scan(&self, packets: Vec<SinglePacket>) -> Option<IP>{
            return SmurfScanner::check_packets(packets);
        }
        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
        }
    }

    ///The function checks if a packets is an icmp packets
    /// or not.
    /// Input: a SinglePacket variable- the packet to check.
    /// Output: a bool value- if is is ICMP or not.
    fn is_icmp_packet(packet: SinglePacket) -> bool{
        let ethernet_packet = match EthernetPacket::new(&packet){
            None => {return false}
            Some(packet) => {packet}
        };
        if let Some(icmp_packet) = IcmpPacket::new(&ethernet_packet.payload()) {
            if icmp_packet.get_icmp_code().0 != 32{
                return true;
            }

        }
        return false;
    }

}