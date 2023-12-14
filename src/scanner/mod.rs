pub mod scanner {
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer;

    // Interface for scanners
    pub trait ScannerFunctions{
        //Public functions
        fn new(ip: IP) -> Self;
        fn scan() -> bool;
        fn check_packets(packets: Vec<SinglePacket>) -> bool;
    }
    pub struct Scanner{
        ip: IP
    }

    impl Scanner{
        ///Default C'tor of struct Scanner
        ///Input: an IP structure- the IP for the Scanner.
        /// Output: The Scanner object Structure.
        pub fn new(ip: IP) -> Self{
            return Scanner{ip: IP::copy(ip)};
        }
    }
}