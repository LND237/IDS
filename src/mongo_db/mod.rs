pub mod mongo_db{
    use chrono::{DateTime, Utc};
    use futures::TryStreamExt;
    use mongodb::bson::{doc, Document};
    use mongodb::{Client, Collection, Database};
    use mongodb::options::{ClientOptions, ServerApi, ServerApiVersion};
    use urlencoding::encode;
    use crate::ip::ip::IP;

    const DB_DOMAIN_PART_1 : &str = "mongodb+srv://";
    const DB_DOMAIN_PART_2 : &str = "@ideproject.jii1z04.mongodb.net/?retryWrites=true&w=majority";
    const DB_NAME : &str = "IDE_DB";
    const IP_ATTACKER_FIELD_NAME : &str = "ip";


    pub struct MongoDB{
        username: String,
        password: String,
        db: Database
    }

    pub struct AttackData{
        ip_attacker: IP,
        attack_name: String,
        date: DateTime<Utc>
    }

    impl Clone for AttackData{
        fn clone(&self) -> Self {
            return self.copy();
        }
    }

    //AttackData function
    impl AttackData{
        //Public Functions
        ///Constructor of struct AttackData.
        /// Input: an IP variable -the ip of the attacker,
        /// a string variable- the name of the attack
        /// and a DateTime<Utc> variable- the time of the attack(Utc).
        pub fn new(ip_attacker: IP, attack_name: String, date: DateTime<Utc>) -> Self{
            return Self{ip_attacker, attack_name, date}
        }

        ///The function gets the ip of the attacker.
        /// Input: None.
        /// Output: an IP value- the ip of the attacker.
        pub fn get_ip_attacker(&self) -> IP{
            return self.ip_attacker.copy();
        }

        ///The function gets the name of the attack.
        /// Input: None.
        /// Output: A string value- the name of the attack.
        pub fn get_attack_name(&self) -> String{
            return self.attack_name.clone();
        }

        /// The function gets the time of the attack.
        /// Input: None.
        /// Output: a dateTime<Utc> value- the time of the attack(as Utc).
        pub fn get_date(&self) -> DateTime<Utc>{
            return self.date;
        }

        ///The function makes a string in json format
        /// from an AttackData structure.
        /// Input: None.
        /// Output: a string value - the json string.
        pub fn get_data_str_json(&self) -> String{
            return format!("{{'ip': '{}', 'name': '{}', 'date': '{}'}}", self.ip_attacker.get_ip(),
                           self.attack_name.clone(), self.date.to_string());
        }

        ///The function copies the AttackData struct.
        /// Input: None.
        /// Output: a value of AttackData- the copied data.
        pub fn copy(&self) -> Self{
            return Self{ip_attacker: self.ip_attacker.copy(), attack_name: self.attack_name.clone(), date: self.date.clone()};
        }
    }

    //MongoDB Functions
    impl MongoDB{
        //Private Function
        ///The function checks if a collection exists in the database.
        /// Input: self reference(MongoDb) and a string variable- the name
        /// of the collection to check.
        /// Output:a boolean value- if the collection exists or not.
        async fn check_collection_existence(&self, collection_name: String) -> bool{
            let collections_names = self.db.list_collection_names(None).await.unwrap();

            return collections_names.contains(&collection_name);
        }

        //Public function
        ///Constructor of struct MongoDB.
        /// Input: 3 string variables- the username, the password and the name of the database.
        /// Output: if there is an error- a mongodb::error, else- self value.
        pub async fn new(username: String, password: String) -> mongodb::error::Result<Self>{
            let encoded_password = encode_string(password.clone());
            let link = build_connection_string(encoded_password, username.clone()).await;

            let client_options = build_client_options(&link).await?;
            let client = create_client(client_options)?;

            ping_mongodb(&client, DB_NAME.to_string().clone()).await?;

            return Ok(Self{username: username.clone(), password: password.clone(), db: get_access_db(client.clone(), DB_NAME.to_string().clone())});
        }

        ///The function gets the username of the database.
        /// Input: None.
        /// Output: A string value- the username for the database.
        pub fn get_username(&self) -> String{
            return self.username.clone();
        }

        ///The function gets the password of the database.
        /// Input: None.
        /// Output: A string value- the password for the database.
        pub fn get_password(&self) -> String{
            return self.password.clone();
        }

        ///The function copies the database structure.
        /// Input: None.
        /// Output: a Self structure(MongoDB)- a copy of the structure.
        pub fn copy(&self) -> Self{
            return Self{username: self.username.clone(), password: self.password.clone(), db: self.db.clone()};
        }

        ///The function adds an attack to the database according to its data and
        /// the collection to insert to(the ip of the client).
        /// Input: a self reference(MongoDB), an IP variable- the ip of the client to insert the
        /// data to and an AttackData variable- the data to insert.
        /// Output: If there is an error- a mongodb::error value.
        pub async fn add_attack(&self, ip_client: IP, data: AttackData) -> mongodb::error::Result<()>{
            let str_ip_client = ip_client.get_ip();

            if !self.check_collection_existence(str_ip_client.clone()).await{
                 match self.db.create_collection(str_ip_client.clone(), None).await{
                     Ok(_) => {}
                     Err(msg) => {return Err(msg)}
                 };
            }

            //Making the document from the AttackData variable
            let attack_doc = doc!{
                "ip": data.get_ip_attacker().get_ip(),
                "name": data.get_attack_name(),
                "date": data.get_date().to_string()
            };

            self.db.collection(&str_ip_client.clone()).insert_one(attack_doc, None).await?;
            Ok(())
        }

        ///The function gets all the attackers of a single client.
        /// Input: a self reference(MongoDB), an IP variable- the ip of the client
        /// to check.
        /// Output: a Vec<IP> value- all the ips of the attackers.
        pub async fn get_all_attackers(&self, ip_client: IP) -> Vec<IP>{
            let mut clients = Vec::new();

            //If the client is already in the database
            if self.check_collection_existence(ip_client.get_ip().clone()).await{
                let collection = self.db.collection(&ip_client.get_ip().clone());
                clients = get_attackers_from_collection(collection).await;

            }

            return clients;
        }

    }

    //Private Static Functions
    ///The function encodes a string to insert it to the url.
    /// Input: a String variable- the string to encode.
    ///Output: a String value- the encoded String.
    fn encode_string(str: String) -> String{
        return String::from(encode(&str));
    }

    ///The function builds the string to connect with to the DB server.
    ///Input: The encoded password to the DB and the username to connect.
    ///Output: The full link to the DB server.
    async fn build_connection_string(encoded_pass: String, username: String) -> String {
        let client_opt_part_1 = String::from(DB_DOMAIN_PART_1);
        let client_opt_part_2 = String::from(DB_DOMAIN_PART_2);
        let link = client_opt_part_1 +  &username + &String::from(":") + &encoded_pass + &client_opt_part_2;
        return link;
    }

    ///The function builds the client options to create the client with.
    ///Input: The string to connect with it to server.
    ///Output: THe client options to connect.
    async fn build_client_options(connection_str: &str) -> mongodb::error::Result<ClientOptions> {
        let mut client_options = ClientOptions::parse(connection_str).await?;
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        Ok(client_options)
    }

    ///The function creates the client and in case of failure return an error.
    ///Input: The client options to create the client with.
    ///Output: The final client to access the database.
    fn create_client(client_options: ClientOptions) -> mongodb::error::Result<Client> {
        Client::with_options(client_options)
    }

    ///The function sends a ping function to the database and checks if it responses.
    ///Input: The client to access the database with.
    ///Output: None unless there is an error.
    async fn ping_mongodb(client: &Client, database_name: String) -> mongodb::error::Result<()> {
        client.database(&database_name.clone()).run_command(doc! {"ping": 1}, None).await?;
        Ok(())
    }

    ///The function makes the actual variable to
    /// access the database from.
    /// Input: a Client variable- the client with the databases and
    /// a String variable- the name of the database.
    /// Output: A Database value- the variable of the database.
    fn get_access_db(client: Client, db_name: String) -> Database{
        return client.clone().database(&db_name.clone());
    }

    ///The function gets the list of the attackers from a collection.
    /// Input: a Collection<Document> variable - the collection to
    /// extract the attackers from.
    /// Output: a Vec<IP> value - the ips of the attackers.
    async fn get_attackers_from_collection(collection: Collection<Document>) -> Vec<IP> {
        let mut attackers = Vec::new();
        let mut cursor = collection.find(None, None).await.unwrap();

        //Going over the Documents by the Cursor
        while let Ok(Some(result)) = cursor.try_next().await{
            attackers.push(IP::new(result.get_str(IP_ATTACKER_FIELD_NAME).unwrap().to_string()).unwrap());
        }
        return attackers;
    }
}