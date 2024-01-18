

pub mod mongo_db{
    use chrono::{DateTime, Utc};
    use mongodb::bson::doc;
    use mongodb::{Client, Database};
    use mongodb::options::{ClientOptions, ServerApi, ServerApiVersion};
    use urlencoding::encode;
    use crate::ip::ip::IP;

    const DB_DOMAIN_PART_1 : &str = "mongodb+srv://";
    const DB_DOMAIN_PART_2 : &str = "@ideproject.jii1z04.mongodb.net/?retryWrites=true&w=majority";


    pub struct MongoDB{
        username: String,
        password: String,
        db: Database
    }

    impl MongoDB{
        async fn check_collection_existence(&self, collection_name: String) -> bool{
            let result = self.db.list_collection_names(None).await;
            let collections_names = match result{
                Ok(val) => {val},
                Err(msg) => {panic!("{}", msg)}
            };

            return collections_names.contains(&collection_name);
        }
        pub async fn new(username: String, password: String, database_name: String) -> mongodb::error::Result<Self>{
            let encoded_password = encode_string(password.clone());
            let link = build_connection_string(encoded_password, username.clone()).await;

            let client_options = build_client_options(&link).await?;
            let client = create_client(client_options)?;

            // ping_mongodb(&client, database_name.clone()).await?;

            return Ok(Self{username: username.clone(), password: password.clone(), db: get_access_db(client.clone(), database_name.clone())});
        }
        pub fn get_username(&self) -> String{
            return self.username.clone();
        }
        pub fn get_password(&self) -> String{
            return self.password.clone();
        }

        pub async fn add_attack(&self, ip_client: IP, ip_attacker: IP, attack_name: String, date: DateTime<Utc>) -> mongodb::error::Result<()>{
            let str_ip_client = ip_client.get_ip();
            if !self.check_collection_existence(str_ip_client.clone()).await{
                 match self.db.create_collection(str_ip_client.clone(), None).await{
                     Ok(_) => {println!("Collection was added")}
                     Err(msg) => {panic!("{}", msg)}
                 };
            }
            let attack_doc = doc!{
                "ip": ip_attacker.get_ip(),
                "name": attack_name.clone(),
                "date": date.to_string()
            };

            self.db.collection(&str_ip_client.clone()).insert_one(attack_doc, None).await?;
            Ok(())
        }
    }
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
        println!("Pinged your deployment. You successfully connected to MongoDB!");
        Ok(())
    }

    fn get_access_db(client: Client, db_name: String) -> Database{
        return client.clone().database(&db_name.clone());
    }
}