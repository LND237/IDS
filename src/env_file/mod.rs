pub mod env_file{
    const ENV_FILE_PATH: &str = "./env_files/variables.env";
    const ERROR_MSG: &str = "Enable to open env file";

    ///The function gets the username from the env file.
    /// Input: None.
    /// Output: a String value- the username from the env file.
    pub fn get_username() -> String{
        dotenv::from_path(ENV_FILE_PATH.to_string()).expect(ERROR_MSG);
        return dotenv::var("USERNAME_DB").unwrap();
    }

    ///The function gets the password from the env file.
    /// Input: None.
    /// Output: a String value- the username from the env file.
    pub fn get_password() -> String{
        dotenv::from_path(ENV_FILE_PATH.to_string()).expect(ERROR_MSG);
        return dotenv::var("PASSWORD_DB").unwrap();
    }

    ///The function gets the api key from the env file.
    /// Input: None.
    /// Output: a String value- the username from the env file.
    pub fn get_api_key() -> String{
        dotenv::from_path(ENV_FILE_PATH.to_string()).expect(ERROR_MSG);
        return dotenv::var("API_KEY_VT").unwrap();
    }
}