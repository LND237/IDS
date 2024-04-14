pub mod mac{
    use std::str::FromStr;
    use macaddr::MacAddr;

    pub const BROADCAST_MAC: &str = "ff:ff:ff:ff:ff:ff";

    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct MAC{
        address: String
    }

    impl MAC{
        ///Constructor of class MAC.
        /// Input: a String variable- the mac as string.
        /// Output: Ok- a Self value, Err- a String value- the
        /// string of the error.
        pub fn new(address: String) -> Result<Self,String> {
            return match is_valid(address.clone()) {
                true => Ok(Self{address }),
                false => Err("Mac address is not valid!".to_string())
            };
        }

        ///Default Constructor of class MAC.
        /// Input: None.
        pub fn new_default() -> Self{
            return Self{address: BROADCAST_MAC.to_string()}
        }

        ///The function gets the mac address as string.
        /// Input: None.
        /// Output: a string value- the mac address.
        pub fn get_mac(&self) -> String{
            return self.address.clone();
        }

        ///The function sets the mac address to
        /// a new one. If the address is not valid- it will not
        /// change it.
        /// Input: a mutable reference Self and a String variable-
        /// the new address.
        /// Output: None.
        pub fn set_mac(&mut self, new_addr: String){
            return match is_valid(new_addr.clone()) {
                true => {self.address = new_addr.clone()}
                false => {}
            }
        }
    }

    ///The function checks if a mac address is valid.
    /// Input: a String variable- the string to check.
    /// Output: a bool value- if it is valid or not.
    fn is_valid(address: String) -> bool{
        return match MacAddr::from_str(address.as_str()){
            Ok(_) => {true}
            Err(_) => {false}
        }
    }
}