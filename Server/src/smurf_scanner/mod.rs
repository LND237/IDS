pub mod smurf_scanner{
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::icmp::IcmpPacket;
    use pnet::packet::Packet;
    use tokio::runtime::Runtime;
    use crate::address::address::Address;
    use crate::scanner::scanner::{Scanner, ScannerFunctions};
    use crate::ip::ip::IP;
    use crate::server::server::{Server};
    use crate::sniffer::sniffer::{extract_ip_src_from_packet, SinglePacket};

    pub const ATTACK_NAME : &str = "Smurf";
    const RATE_LIMIT: i32 = 300;
    const REPLAY_ICMP_CODE : i32 = 0;

    #[derive(Clone)]
    pub struct SmurfScanner{
        base: Scanner
    }

    impl SmurfScanner{
        ///Constructor of DdosScanner struct.
        /// Input: an IP struct- the ip to scan.
        /// Output: a struct of SmurfScanner.
        pub fn new(ip: IP) -> Self{
            return SmurfScanner{base: Scanner::new(ip.clone(), String::from(ATTACK_NAME))};
        }

        ///The function checks the packets which was sniffed before
        /// and decides if there was a Smurf Attack or not.
        /// Input: A vector of SinglePackets- the packets to check and an
        /// IP variable- the ip of the client.
        /// Output: An IP Value- the IP who did the attack(if
        /// there is no attack-returning default IP Broadcast)
        fn check_packets(packets: Vec<SinglePacket>, client_ip: IP) -> Option<IP> {
            let mut amount_icmp_packets = 0;
            //Going over the packets
            for packet in packets{
                if is_icmp_replay_packet(packet.clone()) && extract_ip_src_from_packet(packet.clone()).get_ip() != client_ip.get_ip(){
                    amount_icmp_packets += 1;
                }
            }
            //Checking if it is over the RATE_LIMIT
            if amount_icmp_packets >= RATE_LIMIT{
                return None; //no specific attacker was recognized
            }
            return Some(IP::new_default());
        }
    }

    impl ScannerFunctions for SmurfScanner{
        ///The function scans the network and checks if there is
        /// a Smurf Attack or not and handles the result.
        /// Input: self reference(SmurfScanner), a Vec<SinglePacket>- the
        /// packets to scan and an Address variable- the address of the client.
        /// Output: None.
        fn scan(&self, packets: Vec<SinglePacket>, client_address: Address){
            let result = SmurfScanner::check_packets(packets, client_address.clone().get_ip());

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

    ///The function checks if a packets is an icmp replay packets
    /// or not.
    /// Input: a SinglePacket variable- the packet to check.
    /// Output: a bool value- if it is icmp replay packet or not.
    fn is_icmp_replay_packet(packet: SinglePacket) -> bool{
        let ethernet_packet = match EthernetPacket::new(&packet){
            None => {return false}
            Some(packet) => {packet}
        };

        if let Some(icmp_packet) = IcmpPacket::new(&ethernet_packet.payload()) {
            if REPLAY_ICMP_CODE as u8 == icmp_packet.get_icmp_code().0{
                return true;
            }

        }
        return false;
    }
}