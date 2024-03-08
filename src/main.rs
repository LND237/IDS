use std::io::stdin;
use crate::ddos_scanner::ddos_scanner::{DDOS_PORT, DdosScanner};
use crate::ip::ip::IP;
use crate::server::server::Server;
use crate::sniffer::sniffer::{filter_packets, get_string_packet, Sniffer};

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
    let ip = IP::new("192.168.1.103".to_string()).unwrap();

    /*const USERNAME: &str = "bsyl";
    const PASSWORD: &str = "zaq1@wsx";


    let ip_vector = vec![ip.copy()];

    let mut server = match Server::new(ip_vector.clone(), USERNAME.to_string(), PASSWORD.to_string()).await{
        Ok(server) => {server}
        Err(msg) => {panic!("{}", msg.to_string())}
    };
    println!("Server started");
    server.run().await;*/

    let mut sniffer = Sniffer::new_default_port(ip.copy());
    let packets = sniffer.sniff(1000, 2);
    let filtered = filter_packets(packets, 443);
    let mut count = 1;
    println!("Amount packets: {}", filtered.len());
    for pack in filtered{
        println!("The packet  no.{} content", count);
        println!("{}", get_string_packet(pack));
        count += 1;
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
/// Output: an IP struct - the ip from the user
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


