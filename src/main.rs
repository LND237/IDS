use std::io::stdin;
use chrono::Utc;
use mongo_db::mongo_db::AttackData;
use crate::communicator::communicator::Communicator;
use crate::ip::ip::IP;

mod ip;
mod sniffer;
mod scanner;
mod ddos_scanner;
mod dns_scanner;
mod mongo_db;
mod spec_scanner;
mod communicator;

#[tokio::main]
async fn main() -> mongodb::error::Result<()> {
    const PORT_NUM : u16 = 50001;
    //Getting the names of the collection and the attacker(their ips)
    println!("Please enter the ip of the client: ");
    let ip_client = get_ip_input();

    println!("Please enter the ip of the attacker: ");
    let ip_attacker = get_ip_input();

    //Example for data to send
    let data = AttackData::new(ip_attacker.copy(),
                               ddos_scanner::ddos_scanner::ATTACK_NAME.to_string(),
                               Utc::now());

    let communicator = Communicator::new(ip_client, PORT_NUM).unwrap();

    communicator.notify_client(data).expect("Nothing");

    Ok(())
}

///The function gets a string input
/// from the user.
/// Input: None.
/// Output: A string value - the input from the user.
fn get_string_input() -> String{
    let mut str = String::new();
    stdin().read_line(&mut str).expect("Failed to read line");
    str = str.trim().to_string();
    return str;
}

///The function gets an ip input from the user
/// Input: None.
/// Output: an IP struct- the ip from the user
fn get_ip_input() -> IP{
    let mut ip = IP::new_default();
    let mut is_ip_valid = false;

    while !is_ip_valid {
        let input = get_string_input();
        //Trying to make an ip from the input
        match IP::new(input.clone()){
            Ok(ip_input) => {
                ip = ip_input;
                is_ip_valid = true;
            }
            Err(msg) => {println!("{}", msg)}
        }
    }
    return ip;
}


