use std::io::stdin;
use chrono::Utc;
use crate::ip::ip::IP;
use crate::server::server::Server;
use local_ip_address::local_ip;
use crate::address::address::Address;
use crate::env_file::env_file::{get_password, get_username};
use crate::mac::mac::MAC;
use mac_address::get_mac_address;
use crate::communicator::communicator::notify_client;
use crate::mongo_db::mongo_db::AttackData;

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
mod env_file;
mod firewall;
mod address;
mod mac;

#[tokio::main]
async fn main() -> mongodb::error::Result<()> {
    let ip = IP::new(local_ip().unwrap().to_string()).unwrap();
    println!("IP: {}", ip.copy().get_ip());
    let mac = MAC::new(get_mac_address().unwrap().unwrap().to_string()).unwrap();
    println!("MAC: {}", mac.clone().get_mac());

    let local_address = Address::new(mac.clone(), ip.clone());

    let username = get_username();
    let password = get_password();

    println!("Username: {}, Password: {}", username.clone(), password.clone());

    let mut address_vector = get_addresses();
    address_vector.push(local_address.clone());

    let mut server = match Server::new(address_vector.clone(), username.clone().to_string(), password.clone().to_string()).await{
        Ok(server) => {server}
        Err(msg) => {panic!("{}", msg.to_string())}
    };
    println!("Server started");
    server.run().await;

    //Example for communicator check
    /*let ip_client = IP::new("192.168.1.139".to_string()).unwrap();
    let data = AttackData::new(IP::new_default(), "DD".to_string(), Utc::now());
    notify_client(ip_client.copy(), 50001, data.clone()).expect("Looser");*/
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

///The function gets an ip input from the user.
/// Input: None.
/// Output: an IP struct - the ip from the user.
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

///The function gets a mac input from the user.
/// Input: None.
/// Output: a MAC struct - the mac from the user.
fn get_mac_input() -> MAC{
    let mut mac = MAC::new_default();
    let mut is_mac_valid = false;

    while !is_mac_valid{
        let input = get_string_input();

        //Trying to make a mac from the input
        match MAC::new(input.clone()){
            Ok(mac_input) => {
                mac = mac_input;
                is_mac_valid = true;
            },
            Err(msg) => {println!("{}", msg)}
        }
    }

    return mac;
}

///The function gets an address input from the user.
/// Input: None.
/// Output: an Address struct - the address from the user.
fn get_address() -> Address{
    println!("Please enter the ip of one of the clients: ");
    let ip = get_ip_input();
    println!("Please enter his mac address: ");
    let mac = get_mac_input();
    return Address::new(mac.clone(), ip.clone());
}

///The function gets a couple of addresses from the user.
/// Input: None.
/// Output: a Vec<Address> value- the given addresses.
fn get_addresses() -> Vec<Address>{
    const EXIT_STR: &str = "exit";
    let mut addresses = Vec::new();
    let mut input = String::new();

    //While the user did not finish to insert addresses
    while !input.eq(&EXIT_STR.to_string()){
        println!("Do you want to add another address? Enter '{}' to finish: ", EXIT_STR);
        input = get_string_input();
        if !input.eq(&EXIT_STR.to_string()){
            println!("So please enter an address");
            addresses.push(get_address());
        }
    }

    return addresses.clone();
}



