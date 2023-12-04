pub mod ip{
    pub const MAX_IP_VALUE: i32 = 255;
    pub struct IP{
        address: String
    }

    fn check_ip(address: &String) -> bool {
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
        pub fn new(address: String) -> Result<IP, String> {
            return match check_ip(&address) {
                true => Ok(IP { address }),
                false => Err("Ip is not valid".to_string())
            }
        }

        pub fn get_ip(&self) -> String {
            return self.address.to_string();
        }

        pub fn set_ip(&mut self, new_addr: String) {
            match check_ip(&new_addr) {
                true => self.address = new_addr.clone(),
                false => ()
            }

        }

        pub fn copy(&self) -> IP {
            return IP{address:self.get_ip()};
        }

    }
}