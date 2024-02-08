pub mod server{
    use std::collections::HashMap;
    use std::ops::DerefMut;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use chrono::Utc;
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

    pub type Scanners = Vec<Box<dyn ScannerFunctions>>;
    pub type Client = (IP, Scanners);

    const PORT_NUM : u16 = 50000;

    pub struct Server{
        clients: HashMap<IP, Scanners>,
        db: MongoDB
    }

    impl Server{
        pub async fn new(ips: Vec<IP>, db_username : String, db_password: String) -> Result<Self, String>{
            //Building the database
            let database = match MongoDB::new(db_username.clone(), db_password.clone()).await{
                Ok(db) => {db},
                Err(msg) => {return Err(msg.to_string())}
            };

            let clients = init_clients(ips.clone(), database.copy()).await;

            return Ok(Self{clients, db: database.copy()});
        }

        pub async fn run(&mut self) {
            let shared_results = Arc::new(Mutex::new(Vec::new()));
            loop {
                let mut tasks = Vec::new();
                for client in self.clients.iter().clone() {
                    let ip_client = client.0.clone();
                    let shared_data = Arc::clone(&shared_results);
                    let scan_result = scan_client(client);
                    let task = async move {
                        let mut data = shared_data.lock().unwrap();
                        data.push((scan_result, ip_client.clone()));
                    };
                    tasks.push(task);
                }

                futures::future::join_all(tasks).await;

                let mut final_data = shared_results.lock().unwrap();
                for result in final_data.iter() {
                    let scan_result = result.clone().0;
                    let ip_client = &result.1;
                    match scan_result {
                        Some(data) => {
                            let database_res = self.db.add_attack(ip_client.clone(), data.clone()).await;
                            let communicator_res = notify_client(ip_client.clone(), PORT_NUM, data.clone());
                        },
                        None => {}
                    }
                }
                final_data.clear();
            }
        }
    }
    async fn init_clients(clients_ips : Vec<IP>, database: MongoDB) -> HashMap<IP, Scanners>{
        let mut clients = HashMap::new();

        //Going over the ips
        for ip in clients_ips{
            //Making the scanners for each ip of the client
            let mut scanners = make_basic_scanners(ip.copy());
            let attackers = database.get_all_attackers(ip.copy()).await;
            let mut spec_scanners = make_spec_scanners(ip.copy(), attackers.clone());
            scanners.append(&mut spec_scanners);

            clients.insert(ip.copy(), scanners);
        }

        return clients;
    }
    fn make_basic_scanners(ip : IP) -> Scanners{
        let mut the_scanners = Scanners::new();

        //Pushing all the basic scanners
        the_scanners.push(Box::new(DdosScanner::new(ip.copy())));
        the_scanners.push(Box::new(SmurfScanner::new(ip.copy())));
        the_scanners.push(Box::new(XssScanner::new(ip.copy())));
        the_scanners.push(Box::new(DnsScanner::new(ip.copy())));
        the_scanners.push(Box::new(DownloadScanner::new(ip.copy())));

        return the_scanners;
    }

    fn make_spec_scanners(ip_client : IP, attackers: Vec<IP>) -> Scanners{
        let mut spec_scanners = Scanners::new();

        //Going over the attackers
        for ip_attacker in attackers{
            spec_scanners.push(Box::new(SpecScanner::new(ip_client.copy(), ip_attacker.copy())));
        }

        return spec_scanners;
    }
    fn scan_client(client: (&IP, &Vec<Box<dyn ScannerFunctions>>)) -> Option<AttackData> {
        let client_clone = client.clone();
        let scanners = client_clone.1.clone();
        let shared_results = Arc::new(Mutex::new(Vec::new()));

        // Collecting the results of all the scanners
        let mut threads = Vec::new();
        for scanner in scanners {
            let scanner = scanner.clone(); // Clone scanner to avoid move
            let shared_results = Arc::clone(&shared_results); // Clone Arc for each thread
            let thread = thread::spawn(move || {
                let ip_result = scanner.scan();
                let base_data_name = scanner.get_base_data().get_name().clone();
                let mut results = shared_results.lock().unwrap();
                results.push((ip_result, base_data_name));
            });
            threads.push(thread);
        }

        // Waiting for all threads to finish
        for thread in threads {
            thread.join().unwrap();
        }

        // Processing the final results
        let final_results = shared_results.lock().unwrap();
        for result in final_results.iter() {
            let attack_name = result.1.clone();

            // Handling the result
            match &result.0 {
                None => {
                    // Unknown attacker
                    return Some(AttackData::new(client.0.clone(), attack_name, Utc::now()));
                }
                Some(ip) => {
                    // If there was an attacker
                    if *ip != *client.0 {
                        return Some(AttackData::new(ip.clone(), attack_name, Utc::now()));
                    }
                }
            }
        }

        None // No attack detected
    }

}