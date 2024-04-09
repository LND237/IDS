pub mod scanner {
    use std::future::Future;
    use tokio::runtime::Runtime;
    use crate::address::address::Address;
    use crate::ip::ip::IP;
    use crate::sniffer::sniffer::SinglePacket;

    // Interface for scanners
    pub trait ScannerFunctions: 'static {
        //Public function for all Scanners

        ///The function scans the attack and handles the result of
        /// the scan.
        /// Input: a self reference, and a Vec<SinglePacket> variables-
        /// the packets to scan.
        /// Output: None.
        fn scan(&self, packets: Vec<SinglePacket>, client_address: Address);

        /// The function gets a copy of the base data(name and ip) of a scanner.
        /// Input: a self reference.
        /// Output: a Scanner value- the base data
        fn get_base_data(&self) -> Scanner;
    }

    #[derive(Clone)]
    pub struct Scanner{
        attack_name: String,
        ip_scan: IP
    }

    impl Scanner{
        ///Constructor of struct Scanner
        ///Input: an Address structure- the address for the Scanner and
        /// a String variable- the name of the attack to scan.
        /// Output: The Scanner object Structure.
        pub fn new(ip: IP, attack_name: String) -> Self{
            return Scanner{ ip_scan: ip.clone(), attack_name: attack_name.clone()};
        }

        ///The function gets the name of the attack which the
        /// scanner scans.
        /// Input: self reference(Scanner).
        /// Output: The name of the attack of the Scanner.
        pub fn get_name(&self) -> String{
            return self.attack_name.clone();
        }

        ///The function gets the address for the
        /// scanner.
        /// Input: self reference(Scanner).
        /// Output: The Address to scan.
        pub fn get_ip(&self) -> IP{
            return self.ip_scan.clone();
        }
    }
    ///The function runs an async function as
    /// a sync function.
    /// Types: T- the type of the returned value and
    /// F- the function to run.
    /// Output- if the function has an output- F
    pub fn run_async_function<F, T>(async_func: F) -> T
        where
            F: Future<Output = T> + Send + 'static,
            T: Send + 'static,
    {
        let rt = Runtime::new().unwrap();
        rt.block_on(async_func)
    }
}