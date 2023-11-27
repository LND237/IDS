
pub trait IpTrait {
    fn new(address: String) -> Result<IP, String>;
    fn get_ip(&self) -> String;
    fn set_ip(&mut self, new_addr: String);
}

pub struct IP{
    address: String
}

impl IpTrait for IP{
    fn new(address: String) -> Result<IP, String> {
        match check_ip(&address) {
            true => return Ok(IP{address}),
            false => return Err("Ip is not valid".to_string())

        }
    }

    fn get_ip(&self) -> String {
        return self.address.clone();
    }

    fn set_ip(&mut self, new_addr: String) {
        match check_ip(&new_addr) {
            true => self.address = new_addr.clone(),
            false => ()
        }

    }
}

fn check_ip(address: &String) -> bool {
    let values_ip = address.split(".");

    for value in values_ip {
        let value_int: i32 = value.parse().unwrap();
        if value_int.is_negative() || value_int > 255{
            return false;
        }
    }

    return true;
}