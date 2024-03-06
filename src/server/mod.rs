pub mod server{
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use chrono::Utc;
    use tokio::runtime::Runtime;
    use crate::ddos_scanner::ddos_scanner::DdosScanner;
    use crate::dns_scanner::dns_scanner::DnsScanner;
    use crate::download_scanner::download_scanner::DownloadScanner;
    use crate::ip::ip::IP;
    use crate::mongo_db::mongo_db::{AttackData, MongoDB};
    use crate::scanner::scanner::ScannerFunctions;
    use crate::smurf_scanner::smurf_scanner::SmurfScanner;
    use crate::spec_scanner::spec_scanner::SpecScanner;
    use crate::xss_scanner::xss_scanner::XssScanner;
    use crate::communicator::communicator::notify_client;

    pub type ScanResults = HashMap<String, Option<IP>>;
    #[derive(Clone)]
    pub struct MultiScanner{
        spec_scanners: Vec<SpecScanner>,
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
            let mut spec_scanners = Vec::new();

            //Making the SpecScanners according to the list of the ips
            for ip in ips_attackers{
                spec_scanners.push(SpecScanner::new(ip_client.copy(), ip.copy()));
            }

            return Self{spec_scanners:spec_scanners.clone(),
                ddos_scanner: DdosScanner::new(ip_client.copy()),
                dns_scanner: DnsScanner::new(ip_client.copy()),
                download_scanner: DownloadScanner::new(ip_client.copy()),
                smurf_scanner: SmurfScanner::new(ip_client.copy()),
                xss_scanner: XssScanner::new(ip_client.copy())};
        }

        ///The function add an attacker to
        /// the other specific scanners.
        /// Input: an IP variable- the ip of the attacker
        pub fn add_attacker(&mut self, attacker: IP){
            let mut contains_attacker = false;

            //Going over the specific scanners
            for scanner in &self.spec_scanners{
                if scanner.get_spec_ip().get_ip() == attacker.copy().get_ip(){
                    contains_attacker = true;
                }
            }

            if !contains_attacker{
                self.spec_scanners.push(SpecScanner::new(self.ddos_scanner.clone().get_base_data().get_ip(), attacker.copy()));
            }
        }

        ///The function goes over all the scanners in the
        /// struct and gets their results.
        /// Input: None.
        /// Output: a ScanResults value- the results.
        pub fn scan_all(&self) -> ScanResults {
            let results = Arc::new(Mutex::new(ScanResults::new()));
            let mut threads = vec![];

            // Spawn threads for each scanner
            self.spawn_scanner_threads(&results, &mut threads);

            // Wait for all threads to finish
            for thread in threads {
                thread.join().expect("Scanner thread panicked");
            }

            // Extract and return the final scan results
            let results_mutex = Arc::try_unwrap(results).expect("Failed to unwrap results Arc");
            let scan_results = results_mutex.into_inner().expect("Failed to obtain scan results");
            scan_results
        }
        ///The function inserts the results to the result's
        /// variable reference by using threads.
        /// Input: an Arc<Mutex<ScanResults>> variable- the place to
        /// insert the results to and a Vec<thread> variable- the place to insert the thread to.
        /// Output: None.
        fn spawn_scanner_threads(&self, results: &Arc<Mutex<ScanResults>>, threads: &mut Vec<thread::JoinHandle<()>>) {
            self.spawn_thread_for_scanner(&self.ddos_scanner, results.clone(), threads);
            self.spawn_thread_for_scanner(&self.dns_scanner, results.clone(), threads);
            self.spawn_thread_for_scanner(&self.download_scanner, results.clone(), threads);
            self.spawn_thread_for_scanner(&self.smurf_scanner, results.clone(), threads);
            self.spawn_thread_for_scanner(&self.xss_scanner, results.clone(), threads);

            //Going over the specific scanners
            for scanner in &self.spec_scanners {
                self.spawn_thread_for_scanner(scanner, results.clone(), threads);
            }
        }

        ///The function makes a thread for a scan function of a scanner.
        /// S: The type of the scanner
        ///Input: S type- the scanner, Arc<Mutex<ScanResults>>- the place to
        /// insert the results to and a Vec<thread> variable- the place to insert the
        /// thread to.
        /// Output: None.
        fn spawn_thread_for_scanner<S>(&self, scanner: &S, results: Arc<Mutex<ScanResults>>, threads: &mut Vec<thread::JoinHandle<()>>)
            where
                S: ScannerFunctions + Clone + Send + 'static,
        {
            let results_clone = results.clone();
            let scanner_clone = scanner.clone();

            let thread_handle = thread::spawn(move || {
                let mut scan_results = results_clone.lock().expect("Failed to acquire results mutex");
                let result = scanner_clone.scan();
                scan_results.insert(scanner_clone.get_base_data().get_name(), result);
            });

            threads.push(thread_handle);
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
        /// activates the scanner of the clients.
        pub async fn run(&mut self) {
            loop {
                let mut threads = Vec::new();

                for (ip, multi_scanner) in self.clients.clone() {
                    let multi_scanner = Arc::new(Mutex::new(multi_scanner));
                    let db_clone = self.db.copy();

                    let thread_handle = thread::spawn(move || {
                        let mut multi_scanner = multi_scanner.lock().unwrap();
                        let results = multi_scanner.scan_all();
                        for (name, result) in results {
                            let ip_clone = ip.copy();
                            let name_clone = name.clone();
                            let rt = Runtime::new().unwrap();
                            // Execute the async function within the runtime
                            rt.block_on(Server::handle_result(db_clone.copy(), ip_clone, name_clone, result, &mut multi_scanner));
                    }});
                    threads.push(thread_handle);
                }

                // Wait for all threads to finish
                for thread in threads {
                    thread.join().unwrap();
                }
            }
        }

        ///The function handles the result of the scan and
        /// acts according to it.
        /// Input: a MongoDB variable- the database to write to,
        ///an IP variable- the ip of the scanned client,
        ///a String variable- the name of the attack which was scanned,
        ///an Option<IP> variable- the result itself and a mutable reference
        /// to a MultiScanner variable- the scanner of the client.
        ///Output: None.
        async fn handle_result(database: MongoDB, ip_client: IP, attack_name: String, result: Option<IP>, client_scanner: &mut MultiScanner){
            println!("Handling the result of the attack {}", attack_name.clone());
            const PORT_NUM : u16 = 50001;
            let mut data_to_send = None;
            match result {
                None => {
                    data_to_send = Some(AttackData::new(IP::new_default(), attack_name.clone(), Utc::now()));
                },
                Some(ip) => {
                    //If an ip of attacker
                    if ip.get_ip() != IP::new_default().get_ip(){
                        data_to_send = Some(AttackData::new(ip.copy(), attack_name.clone(), Utc::now()));
                        client_scanner.add_attacker(ip.copy());
                    }
                }
            }
            //If the variable was implemented
            if let Some(the_data) = data_to_send{
                println!("{}", attack_name.clone());
                // let _ = database.add_attack(ip_client.copy(), the_data.copy()).await;
                /*let _ = match notify_client(ip_client.copy(), PORT_NUM, the_data.copy()){
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