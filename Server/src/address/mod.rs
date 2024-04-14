pub mod address{
    use crate::mac::mac::MAC;
    use crate::ip::ip::IP;

    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct Address{
        ip: IP,
        mac: MAC
    }

    impl Address{
        ///Constructor of class Address.
        ///Input: a MAC variable and an IP variable- the address.
        pub fn new(mac: MAC, ip: IP) -> Self{
            return Self{ip: ip.clone(), mac: mac.clone()};
        }

        ///Default Constructor of class Address.
        /// Input: None.
        pub fn new_default() -> Self{
            return Self{ip: IP::new_default(), mac: MAC::new_default()};
        }

        ///The function gets the ip of the address.
        ///Input: a self reference.
        /// Output: An IP value- the ip of the address.
        pub fn get_ip(&self) -> IP{
            return self.ip.clone();
        }

        ///The function gets the mac of the address.
        /// Input: a self reference.
        /// Output: A MAC value- the mac of the address.
        pub fn get_mac(&self) -> MAC{
            return self.mac.clone();
        }
    }
}