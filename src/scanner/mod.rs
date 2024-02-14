pub mod scanner {
    use crate::ip::ip::IP;

    // Interface for scanners
    pub trait ScannerFunctions: 'static {
        //Public function for all Scanners
        fn scan(&self) -> Option<IP>;
        fn get_base_data(&self) -> Scanner;
    }

    #[derive(Clone)]
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

        ///The function copies the structure.
        /// Input: None.
        /// Output: a Self value(Scanner)- a copy.
        pub fn copy(&self) -> Self{
            return Self{attack_name: self.attack_name.clone(), ip: self.ip.copy()};
        }
    }
}