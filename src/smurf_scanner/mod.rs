pub mod smurf_scanner{
    use pnet::packet::icmp::IcmpPacket;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, ALL_PORTS, SinglePacket};

    pub const ATTACK_NAME : &str = "Smurf";
    pub const SMURF_PORT: u16 = ALL_PORTS;
    const AMOUNT_PACKETS_SNIFF: i32 = 100000;
    const TIME_SNIFF: i32 = 5;
    const RATE_LIMIT: i32 = 20000;

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
        fn scan(&self) -> Option<IP>{
            let mut sniffer = Sniffer::new(self.base.get_ip(), SMURF_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
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
        if let Some(_) = IcmpPacket::new(&packet) {
            return true;
        }
        return false;
    }

}