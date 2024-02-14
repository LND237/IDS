pub mod server{
    use std::collections::HashMap;
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

        pub fn scan_all(&self) -> ScanResults {
            let mut results = ScanResults::new();

            //Going over special scanners
            results.insert(self.ddos_scanner.get_base_data().get_name(), self.ddos_scanner.scan());
            results.insert(self.dns_scanner.get_base_data().get_name(), self.dns_scanner.scan());
            results.insert(self.download_scanner.get_base_data().get_name(), self.download_scanner.scan());
            results.insert(self.smurf_scanner.get_base_data().get_name(), self.smurf_scanner.scan());
            results.insert(self.xss_scanner.get_base_data().get_name(), self.xss_scanner.scan());

            //Going over specific scanners
            for scanner in self.spec_scanners.clone(){
                results.insert(scanner.get_base_data().get_name(), scanner.scan());
            }

            return results.clone();
        }
    }

    pub struct Server{
        clients: HashMap<IP, MultiScanner>,
        db: MongoDB
    }

    impl Server{
        pub async fn new(ips: Vec<IP>, db_username : String, db_password: String) -> Result<Self, String>{
            //Building the database
            let database = match MongoDB::new(db_username.clone(), db_password.clone()).await{
                Ok(db) => {db},
                Err(msg) => {return Err(msg.to_string())}
            };

            let the_clients = init_clients(ips.clone(), database.copy()).await;

            return Ok(Self{clients : the_clients, db: database.copy()});
        }

        pub async fn run(&mut self) {
            loop {
                for client in self.clients.clone(){
                    let results = client.1.scan_all();

                    for result in results{
                        self.handle_result(client.0.copy(), result.0.clone(), result.1).await;
                    }
                }
            }
        }

        async fn handle_result(&self, ip_client: IP, attack_name: String, result: Option<IP>){
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
                    }
                }
            }
            //If the variable was implemented
            if let Some(the_data) = data_to_send{
                let _ = self.db.add_attack(ip_client.copy(), the_data.copy()).await;
                let _ = notify_client(ip_client.copy(), PORT_NUM, the_data.copy());
            }
        }
    }
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