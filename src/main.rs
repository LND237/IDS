use urlencoding::encode;
use mongodb::{bson::doc, options::{ClientOptions, ServerApi, ServerApiVersion}, Client, bson};
use std::io::stdin;

mod ip;
use ip::IpTrait;
#[tokio::main]
async fn main() -> mongodb::error::Result<()> {
    let the_ip = <ip::IP as IpTrait>::new(String::from("-1.0.0.1"));
    match  the_ip{
        Err(msg) => println!("{}", msg),
        Ok(ip) => println!("Ip is valid")
    }
    let encoded_password = String::from(encode("zaq1@wsx"));
    let username = String::from("bsyl");
    let link = build_connection_string(encoded_password, username).await;

    let client_options = build_client_options(&link).await?;
    let client = create_client(client_options)?;

    ping_mongodb(&client).await?;
    let (name, age, occupation) = get_user_input();
    let document = create_document(&name, age, &occupation);

    insert_document(&client, document).await?;

    Ok(())
}

/*
The function creates the document to insert to the database.
Input: The name, age and occupation for the document.
Output: The document to insert.
 */
fn create_document(name: &str, age: i32, occupation: &str) -> bson::Document {

    return doc! {
        "name": name,
        "age": age,
        "occupation": occupation.trim(),
    }
}

/*
The function gets the input from the user to enter to the document.
Input: None.
Output: The user's input- the name, age and occupation for the document.
 */
fn get_user_input() -> (String, i32, String) {
    println!("Enter the name:");
    let mut name = String::new();
    stdin().read_line(&mut name).expect("Failed to read line");

    // Trim the newline character from the input
    let name = name.trim().to_string();

    println!("Enter the age:");
    let mut age_str = String::new();
    stdin().read_line(&mut age_str).expect("Failed to read line");
    let age: i32 = age_str.trim().parse().expect("Invalid age");

    println!("Enter the occupation:");
    let mut occupation = String::new();
    stdin().read_line(&mut occupation).expect("Failed to read line");

    (name, age, occupation.trim().to_string())
}

/*
The function builds the string to connect with to the DB server.
Input: The encoded password to the DB and the username to connect.
Output: The full link to the DB server.
 */
async fn build_connection_string(encoded_pass: String, username: String) -> String {
    let client_opt_part_1 = String::from("mongodb+srv://");
    let client_opt_part_2 = String::from("@ideproject.jii1z04.mongodb.net/?retryWrites=true&w=majority");
    let link = client_opt_part_1 +  &username + &String::from(":") + &encoded_pass + &client_opt_part_2;
    return link;
}

/*
The function builds the client options to create the client with.
Input: The string to connect with it to server.
Output: THe client options to connect.
 */
async fn build_client_options(connection_str: &str) -> mongodb::error::Result<ClientOptions> {
    let mut client_options = ClientOptions::parse(connection_str).await?;
    let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
    client_options.server_api = Some(server_api);
    Ok(client_options)
}

/*
The function creates the client and in case of failure return an error.
Input: The client options to create the client with.
Output: The final client to access the database.
 */
fn create_client(client_options: ClientOptions) -> mongodb::error::Result<Client> {
    Client::with_options(client_options)
}

/*
The function sends a ping function to the database and checks if it responses.
Input: The client to access the database with.
Output: None unless there is an error.
 */
async fn ping_mongodb(client: &Client) -> mongodb::error::Result<()> {
    client.database("IDE_DB").run_command(doc! {"ping": 1}, None).await?;
    println!("Pinged your deployment. You successfully connected to MongoDB!");
    Ok(())
}

/*
The function inserts a document to the database.
Input: The client to access the database with and the document to insert.
Output: None.
 */
async fn insert_document(client: &Client, document: bson::Document) -> mongodb::error::Result<()> {
    client
        .database("IDE_DB")
        .collection("try_collection")
        .insert_one(document, None)
        .await?;
    println!("Document was added");
    Ok(())
}