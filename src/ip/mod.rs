pub mod ip{
    pub const MAX_IP_VALUE: i32 = 255;
    pub struct IP{
        address: String
    }
    //private function
    ///The function checks if a string can be
    /// an IP or not.
    /// Input: A reference to string variable- the string
    /// to check.
    /// Output: a bool value - if it can be an IP or not.
    fn check_ip(address: &String) -> bool {
        //Trying to split the "ip" to numbers
        let binding = String::from(".");
        let values_ip = address.split(&binding);

        for value in values_ip {
            let value_int: i32 = value.parse().unwrap();
            if value_int.is_negative() || value_int > MAX_IP_VALUE{
                return false;
            }
        }

        return true;
    }

    impl IP{
        ///Constructor of struct IP.
        /// Input: a String value- the ip.
        pub fn new(address: String) -> Result<IP, String> {
            return match check_ip(&address) {
                true => Ok(IP { address }),
                false => Err("Ip is not valid".to_string())
            }
        }
        ///The function gets the ip from the IP structure.
        /// Input: self reference(IP)
        /// Output: a string value- the address of the ip.
        pub fn get_ip(&self) -> String {
            return self.address.to_string();
        }

        ///The function sets the ip of the structure(if it is valid).
        /// Input: mut reference self(IP) and a string variable-
        /// the new address.
        /// Output: None.
        pub fn set_ip(&mut self, new_addr: String) {
            match check_ip(&new_addr) {
                true => self.address = new_addr.clone(),
                false => ()
            }

        }

        ///The function copies an IP structure.
        ///Input: reference self(IP).
        /// Output: an IP struct- a copy of the self struct.
        pub fn copy(&self) -> IP {
            return IP{address:self.get_ip()};
        }

    }
}