pub mod server{
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::{thread, time};
    use chrono::Utc;
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


    const MAX_AMOUNT_OF_PACKETS : i32 = 1000;
    const SNIFF_TIME: i32 = 3;
    #[derive(Clone)]
    pub struct MultiScanner{
        ddos_scanner : DdosScanner,
        dns_scanner : DnsScanner,
        download_scanner : DownloadScanner,
        smurf_scanner : SmurfScanner,
        xss_scanner: XssScanner
    }

    impl MultiScanner{
        ///Constructor of struct MultiScanner.
        ///Input: an IP variable- the ip of the client to scan and
        /// a Vec<IP> variable- the attackers of the client.
        /// Output: A Self value(MultiScanner).
        pub fn new(ip_client: IP, ips_attackers: Vec<IP> ) -> Self{

            //The ips of the attacker should be implemented in the firewall
            // at the beginning

            return Self{
                ddos_scanner: DdosScanner::new(ip_client.copy()),
                dns_scanner: DnsScanner::new(ip_client.copy()),
                download_scanner: DownloadScanner::new(ip_client.copy()),
                smurf_scanner: SmurfScanner::new(ip_client.copy()),
                xss_scanner: XssScanner::new(ip_client.copy())};
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
            let mut sniffer = Sniffer::new_default_port(self.clone().ddos_scanner.get_base_data().get_ip());
            let packets = sniffer.sniff(MAX_AMOUNT_OF_PACKETS, SNIFF_TIME);
            println!("Total amount: {}", packets.clone().len());

            //Initiating the threads for all the scanners
            MultiScanner::spawn_thread_for_scanner(self.clone().ddos_scanner.clone(), packets.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().dns_scanner.clone(), packets.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().download_scanner.clone(), packets.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().smurf_scanner.clone(), packets.clone());
            MultiScanner::spawn_thread_for_scanner(self.clone().xss_scanner.clone(), packets.clone());
        }

        ///The function makes a thread for a scan function of a scanner.
        /// S: The type of the scanner
        ///Input: S type- the scanner and a Vec<SinglePacket> variable- the
        /// packets to scan.
        /// Output: None.
        fn spawn_thread_for_scanner<S>(scanner: S, packets: Vec<SinglePacket>)
            where
                S: ScannerFunctions + Clone + Send + 'static,
        {
            let scanner_clone = scanner.clone();

            thread::spawn(move || {
                scanner_clone.scan(packets);
            });
        }
    }

    pub struct Server{
        clients: HashMap<IP, MultiScanner>,
        db: MongoDB
    }

    impl Server{

        ///Constructor of struct Server.
        /// Input: a Vec<IP> variable- the ips of the clients and
        /// 2 String variables- the username and the password for accessing
        /// the database.
        /// Output: A Self value(Server)[If there is an error,
        /// returning String msg value]
        pub async fn new(ips: Vec<IP>, db_username : String, db_password: String) -> Result<Self, String>{
            //Building the database
            let database = match MongoDB::new(db_username.clone(), db_password.clone()).await{
                Ok(db) => {db},
                Err(msg) => {return Err(msg.to_string())}
            };

            let the_clients = init_clients(ips.clone(), database.copy()).await;

            return Ok(Self{clients : the_clients, db: database.copy()});
        }

        ///The function starts to run the server and
        /// activates the multi scanners of each client.
        /// Input: None.
        /// Output: None.
        pub async fn run(&mut self) {
            loop {
                let mut threads = Vec::new();

                for (_, multi_scanner) in self.clients.clone() {
                    let multi_scanner = Arc::new(Mutex::new(multi_scanner));

                    let thread_handle = thread::spawn(move || {
                        let mut multi_scanner = multi_scanner.lock().unwrap();
                        multi_scanner.scan_all();
                    });
                    threads.push(thread_handle);
                }

                // Wait for all threads to finish
                for thread in threads {
                    thread.join().unwrap();
                }
                tokio::time::sleep(time::Duration::from_secs(1)).await;
            }
        }

        ///The function handles the result of the scan and
        /// acts according to it.
        /// Input: an IP variable- the ip of the scanned client,
        ///a String variable- the name of the attack which was scanned,
        ///an Option<IP> variable- the result itself.
        ///Output: None.
        pub async fn handle_result(ip_client: IP, attack_name: String, result: Option<IP>){
            const PORT_NUM : u16 = 50001;
            const AMOUNT_SECONDS_BLOCKING_ICMP: i32 = 10;
            let mut data_to_send = None;
            match result {
                None => {
                    block_icmp_limited_time(AMOUNT_SECONDS_BLOCKING_ICMP).await;
                    data_to_send = Some(AttackData::new(IP::new_default(), attack_name.clone(), Utc::now()));
                },
                Some(ip) => {
                    match block_ip(ip.copy()){
                        Ok(_) => {}
                        Err(e) => {
                            println!("Error firewall: {}", e.to_string());
                        }
                    };
                    //If an ip of attacker
                    if ip.copy().get_ip() != IP::new_default().get_ip(){
                        data_to_send = Some(AttackData::new(ip.copy(), attack_name.clone(), Utc::now()));
                    }
                }
            }
            //If the variable was implemented
            if let Some(the_data) = data_to_send{
                println!("{} from {}", attack_name.clone(), the_data.copy().get_ip_attacker().get_ip());
                /*let database = MongoDB::new_default().await.unwrap();
                let _ = database.add_attack(ip_client.copy(), the_data.copy()).await;
                let _ = match notify_client(ip_client.copy(), PORT_NUM, the_data.copy()){
                    Ok(_) => {println!("Data sent to client successfully!")}
                    Err(msg) => {println!("Err client: {}", msg.to_string())}
                };*/
            }
        }
    }

    ///The function inits the data of the scanners about all the clients.
    /// Input: a Vec<IP> variable- the ips of the clients and a
    /// MongoDB variable- the database with the attackers of the
    /// clients.
    /// Output: a HashMap<IP, MultiScanner>- the scanners for all the clients.
    async fn init_clients(clients_ips : Vec<IP>, database: MongoDB) -> HashMap<IP, MultiScanner> {
        let mut clients = HashMap::new();

        //Going over the ips
        for ip in clients_ips{
            clients.insert(ip.copy(),
                           MultiScanner::new(ip.copy(),
                                             database.get_all_attackers(ip.copy()).await));
        }

        return clients;
    }
}