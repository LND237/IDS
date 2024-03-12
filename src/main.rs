use std::io::stdin;
use crate::ip::ip::IP;
use crate::server::server::Server;
use dotenv::dotenv;
use local_ip_address::local_ip;

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
    dotenv::from_path("./env_files/variables.env").expect("Enable to open env file");
    let ip = IP::new(local_ip().unwrap().to_string()).unwrap();
    println!("IP: {}", ip.copy().get_ip());

    let username: &str = &dotenv::var("USERNAME_DB").unwrap();
    let password: &str = &dotenv::var("PASSWORD_DB").unwrap();

    let ip_vector = vec![ip.copy()];

    let mut server = match Server::new(ip_vector.clone(), username.to_string(), password.to_string()).await{
        Ok(server) => {server}
        Err(msg) => {panic!("{}", msg.to_string())}
    };
    println!("Server started");
    server.run().await;
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


