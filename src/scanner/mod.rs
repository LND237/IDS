pub mod scanner {
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::SinglePacket;

    // Interface for scanners
    pub trait ScannerFunctions{
        //Public functions
        fn new(ip: IP) -> Self;
        fn scan(&self) -> IP;
        fn check_packets(packets: Vec<SinglePacket>) -> IP;
    }
    pub struct Scanner{
        attack_name: String,
        ip: IP
    }

    impl Scanner{
        ///Constructor of struct Scanner
        ///Input: an IP structure- the IP for the Scanner and
        /// a String variable- the name of the attack to scan.
        /// Output: The Scanner object Structure.
        pub fn new(ip: IP, attack_name: String) -> Self{
            return Scanner{ip: ip.copy(), attack_name: attack_name.clone()};
        }

        ///The function gets the name of the attack which the
        /// scanner scans.
        /// Input: self reference(Scanner).
        /// Output: The name of the attack of the Scanner.
        pub fn get_name(&self) -> String{
            return self.attack_name.clone();
        }

        ///The function gets the IP for the
        /// scanner.
        /// Input: self reference(Scanner).
        /// Output: The IP to scan.
        pub fn get_ip(&self) -> IP{
            return self.ip.copy();
        }
    }
}