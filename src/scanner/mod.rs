pub mod scanner {
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer;

    // Interface for scanners
    pub trait ScannerFunctions{
        //Public functions
        fn new(ip: IP) -> Self;
        fn scan() -> bool;
    }
    pub struct Scanner{
        ip: IP
    }

    impl Scanner{
        pub fn new(ip: IP) -> Self{
            return Scanner{ip: IP::copy(ip)};
        }
    }
}