pub mod server{
    use std::sync::{Arc, Mutex};
    use std::{thread, time};
    use chrono::Utc;
    use crate::address::address::Address;
    use crate::communicator::communicator::notify_client;
    use crate::ddos_scanner::ddos_scanner::DdosScanner;
    use crate::dns_scanner::dns_scanner::DnsScanner;
    use crate::download_scanner::download_scanner::DownloadScanner;
    use crate::firewall::firewall::{block_icmp_limited_time, block_ip};
    use crate::ip::ip::IP;
    use crate::mongo_db::mongo_db::{AttackData, MongoDB};
    use crate::scanner::scanner::ScannerFunctions;
    use crate::smurf_scanner::smurf_scanner::SmurfScanner;
    use crate::xss_scanner::xss_scanner::XssScanner;
    use crate::sniffer::sniffer::{SinglePacket, Sniffer};
    use local_ip_address::local_ip;



    const MAX_AMOUNT_OF_PACKETS : i32 = 1000;
    const SNIFF_TIME: i32 = 3;
    #[derive(Clone)]
    pub struct MultiScanner{
        client_address: Address,
        ddos_scanner : DdosScanner,
        dns_scanner : DnsScanner,
        download_scanner : DownloadScanner,
        smurf_scanner : SmurfScanner,
        xss_scanner: XssScanner
    }

    impl MultiScanner{
        ///Constructor of struct MultiScanner.
        ///Input: an Address variable- the address of the client to scan.
        /// Output: A Self value(MultiScanner).
        pub fn new(address_client: Address) -> Self{
            let self_ip = IP::new(local_ip().unwrap().to_string()).unwrap();
            return Self{
                client_address: address_client.clone(),
                ddos_scanner: DdosScanner::new(self_ip.clone()),
                dns_scanner: DnsScanner::new(self_ip.clone()),
                download_scanner: DownloadScanner::new(self_ip.clone()),
                smurf_scanner: SmurfScanner::new(self_ip.clone()),
                xss_scanner: XssScanner::new(self_ip.clone())};
        }

        ///The function goes over all the scanners in the
        /// struct and gets their results.
        /// Input: a mutable self reference.
        /// Output: None.
        pub fn scan_all(&mut self){
            // Spawn threads for each scanner
            self.spawn_scanner_threads();
        }

        ///The function makes the threads for all the scanners
        /// in the MultiScanner.
        /// Input: a mutable self reference.
        /// Output: None.
        fn spawn_scanner_threads(&mut self) {
            //Sniffing the packets to scan
            let mut sniffer = Sniffer::new_default_port(self.client_address.get_ip());
            let packets = sniffer.sniff(MAX_AMOUNT_OF_PACKETS, SNIFF_TIME);
            let client_address = self.clone().client_address.clone();
            println!("Total amount: {}", packets.clone().len());

            //Initiating the threads for all the scanners
            MultiScanner::spawn_thread_for_scanner(self.clone().ddos_scanner.clone(), packets.clone(), client_address.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().dns_scanner.clone(), packets.clone(), client_address.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().download_scanner.clone(), packets.clone(), client_address.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().smurf_scanner.clone(), packets.clone(), client_address.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().xss_scanner.clone(), packets.clone(), client_address.clone());
        }

        ///The function makes a thread for a scan function of a scanner.
        /// S: The type of the scanner
        ///Input: S type- the scanner and a Vec<SinglePacket> variable- the
        /// packets to scan.
        /// Output: None.
        fn spawn_thread_for_scanner<S>(scanner: S, packets: Vec<SinglePacket>, address_client: Address)
            where
                S: ScannerFunctions + Clone + Send + 'static,
        {
            let scanner_clone = scanner.clone();

            thread::spawn(move || {
                scanner_clone.scan(packets, address_client.clone());
            });
        }
    }

    pub struct Server{
        client: MultiScanner,
        db: MongoDB
    }

    impl Server{

        ///Constructor of struct Server.
        /// Input: a Vec<Address> variable- the addresses of the clients and
        /// 2 String variables- the username and the password for accessing
        /// the database.
        /// Output: A Self value(Server)[If there is an error,
        /// returning String msg value]
        pub async fn new(client: Address, db_username : String, db_password: String) -> Result<Self, String>{
            //Building the database
            let database = match MongoDB::new(db_username.clone(), db_password.clone()).await{
                Ok(db) => {db},
                Err(msg) => {return Err(msg.to_string())}
            };

            let the_client = init_client(client.clone(), database.copy()).await;

            return Ok(Self{ client: the_client, db: database.copy()});
        }

        ///The function starts to run the server and
        /// activates the multi scanners of each client.
        /// Input: None.
        /// Output: None.
        pub async fn run(&mut self) {
            loop {
                //Getting the MultiScanner
                let the_multi_scanner = self.client.clone();
                let multi_scanner = Arc::new(Mutex::new(the_multi_scanner));

                let _ = thread::spawn(move || {
                    let mut multi_scanner = multi_scanner.lock().unwrap();
                    multi_scanner.scan_all();
                }).join();
                tokio::time::sleep(time::Duration::from_secs(1)).await;
            }
        }

        ///The function handles the result of the scan and
        /// acts according to it.
        /// Input: an Address variable- the address of the scanned client,
        ///a String variable- the name of the attack which was scanned,
        ///an Option<IP> variable- the result itself.
        ///Output: None.
        pub async fn handle_result(address_client: Address, attack_name: String, result: Option<IP>){
            const PORT_NUM : u16 = 50001;
            const AMOUNT_SECONDS_BLOCKING_ICMP: i32 = 10;
            let mut data_to_send = None;
            match result {
                None => {
                    block_icmp_limited_time(AMOUNT_SECONDS_BLOCKING_ICMP).await;
                    data_to_send = Some(AttackData::new(IP::new_default(), attack_name.clone(), Utc::now()));
                },
                Some(ip) => {
                    //If an ip of attacker
                    if ip.copy().get_ip() != IP::new_default().get_ip(){
                        data_to_send = Some(AttackData::new(ip.copy(), attack_name.clone(), Utc::now()));
                        match block_ip(ip.copy()){
                            Ok(_) => {}
                            Err(e) => {
                                println!("Error firewall: {}", e.to_string());
                            }
                        };
                    }
                }
            }
            //If the variable was implemented
            if let Some(the_data) = data_to_send{
                println!("{} from {}", attack_name.clone(), the_data.copy().get_ip_attacker().get_ip());
                //Adding data to database
                let database = MongoDB::new_default().await.unwrap();
                let _ = database.add_attack(address_client.clone().get_mac(), the_data.copy()).await;
                //Notifying the client about the attack
                let _ = match notify_client(address_client.get_ip().copy(), PORT_NUM, the_data.copy()){
                    Ok(_) => {println!("Data sent to client successfully!")}
                    Err(msg) => {println!("Err client: {}", msg.to_string())}
                };
            }
        }
    }

    ///The function inits the data of the scanners about all the clients.
    /// Input: a Vec<Address> variable- the addresses of the clients and a
    /// MongoDB variable- the database with the attackers of the
    /// clients.
    /// Output: a HashMap<Address, MultiScanner>- the scanners for all the clients.
    async fn init_client(client_address : Address, database: MongoDB) -> MultiScanner{
        let ips_attackers = database.get_all_attackers(client_address.clone().get_mac()).await;

        //Implementing firewall rules for all the attackers
        for ip in ips_attackers{
            let _ = block_ip(ip.copy());
        }

        return MultiScanner::new(client_address.clone());
    }
}