use std::io::stdin;
use crate::ip::ip::IP;
use crate::sniffer::sniffer::{get_string_packet, Sniffer};

mod ip;
mod sniffer;
mod scanner;
mod ddos_scanner;
mod dns_scanner;
mod mongo_db;
mod spec_scanner;
mod communicator;
mod xss_scanner;
mod download_scanner;
mod smurf_scanner;
mod server;

#[tokio::main]
async fn main() -> mongodb::error::Result<()> {
    let ip = IP::new("192.168.1.180".to_string()).unwrap();
    let mut sniffer = Sniffer::new(ip.copy(), 443).unwrap();
    let packets = sniffer.sniff(50, 10);
    println!("Packets amount: {}", packets.len());
    for packet in packets{
        println!{"{}", get_string_packet(&packet)};
    }
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


