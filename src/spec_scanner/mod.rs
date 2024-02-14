pub mod spec_scanner{
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::{Sniffer, ALL_PORTS, SinglePacket, extract_ip_src_from_packet};

    const SPEC_ATTACK_PORT: u16 = ALL_PORTS;
    const SPEC_ATTACK_NAME: &str = "REPEAT_ATTACK";
    const AMOUNT_PACKETS_SNIFF: i32 = 50;
    const TIME_SNIFF: i32 = 10;

    #[derive(Clone)]
    pub struct SpecScanner{
        base: Scanner,
        spec_ip: IP
    }

    impl SpecScanner{
        ///Constructor of struct SpecScanner.
        /// Input: 2 IP variables- the ips of the client to
        /// defend and the attacker to block.
        pub fn new(ip_client: IP, ip_attacker: IP) -> Self {
            return Self{base: Scanner::new(ip_client.copy(), SPEC_ATTACK_NAME.to_string()), spec_ip: ip_attacker.copy()};
        }

        ///The function gets the ip to defend from.
        /// Input: None.
        /// Output: an IP value- a copy of the ip to block.
        pub fn get_spec_ip(&self) -> IP{
            return self.spec_ip.copy();
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was an attack from the specific
        /// attacker or not.
        /// Input: A self reference(SpecScanner) and a vector of SinglePackets- the packets to check.
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(&self, packets: Vec<SinglePacket>) -> Option<IP> {
            //Going over the packets
            for packet in packets{
                let ip_src_packet = extract_ip_src_from_packet(packet);
                //If the packet is from an attacker
                if ip_src_packet.copy().get_ip() == self.get_spec_ip().get_ip(){
                    return Some(ip_src_packet.copy());
                }
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for SpecScanner{
        ///The function scans the network and checks if there is
        /// a Specific Attack or not.
        /// Input: self reference(SpecScanner)
        /// Output: An IP Value- the IP of the attacker(if
        /// there is no attack -returning default IP Broadcast).
        fn scan(&self) -> Option<IP> {
            let mut sniffer = Sniffer::new(self.base.get_ip(), SPEC_ATTACK_PORT).unwrap();
            let packets = sniffer.sniff(AMOUNT_PACKETS_SNIFF, TIME_SNIFF);
            return self.check_packets(packets);
        }

        ///The function gets the base data of it.
        /// Input: None.
        /// Output: a Scanner value- the base data.
        fn get_base_data(&self) -> Scanner {
            return self.base.copy();
        }
    }

}