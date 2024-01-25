pub mod communicator{
    use std::net::TcpStream;
    use std::io::Write;
    use crate::ip::ip::IP;
    use crate::mongo_db::mongo_db::AttackData;

    pub const MIN_PORT_NUM : u16 = 50000;

    pub struct Communicator{
        ip_dest: IP,
        port: u16
    }

    impl Communicator{
        //Private Function
        ///The function makes the string to use for connecting to the
        /// server in the client.
        /// Input: None.
        /// Output: a String value- the string to connect with.
        fn build_connection_str_tcp(&self) -> String{
            return build_connection_str_tcp(self.get_ip_dest(), self.get_port_num());
        }

        //Public Functions
        ///Constructor of struct Communicator
        /// Input: an IP variable- the ip to connect to and
        /// an u16 variable- the port to connect to.
        /// Output: a Self reference(Communicator). If the port
        /// is not valid - an Error Result.
        pub fn new(ip: IP, port: u16) -> Result<Self, String> {
            return match is_port_valid(port){
                true => Ok(Self{ ip_dest: ip.copy(), port }),
                false => Err("Invalid port number!".to_string())
            }
        }

        ///The function gets the ip to connect to.
        /// Input: None.
        /// Output: an Ip variable- the ip.
        pub fn get_ip_dest(&self) -> IP{
            return self.ip_dest.copy();
        }

        ///The function gets the number of the port which
        /// the communicator use.
        /// Input: None.
        /// Output: an u16 value- the port.
        pub fn get_port_num(&self) -> u16{
            return self.port;
        }

        ///The function connects to the client's server and sends
        /// the data of the attack to it.
        /// Input: an AttackData variable- the data to send.
        /// Output: a Result<(), String>- if the sending went well.
        pub fn notify_client(&self, data: AttackData) -> Result<(), String> {
            let mut stream = TcpStream::connect(self.build_connection_str_tcp().clone()).expect("Failed to connect to server");
            let data_to_send = data.get_data_str_json();

            stream.write_all(data_to_send.as_bytes()).expect("Failed to send data!");

            return Ok(());
        }

    }
    //Private Static Functions
    /// The function checks if a port is absolutely
    /// valid(above a certain number).
    /// Input: an u16 variable- the number of port to check.
    /// Output: a bool value- if the port is valid or not.
    fn is_port_valid(port: u16) -> bool{
        return port > MIN_PORT_NUM;
    }

    ///The function makes the string to use for connecting to the
    /// server in the client.
    /// Input: an IP variable- the ip to connect to and an
    /// u16 variable- the destination port to use.
    /// Output: a String value- the string to connect with.
    fn build_connection_str_tcp(ip_dest: IP, port: u16) -> String{
        return ip_dest.get_ip() + ":" + &port.to_string();
    }

    ///The function connects to the client's server and sends
    /// the data of the attack to it.
    /// Input: an AttackData variable- the data to send ,
    /// an IP variable- the ip to connect to and an
    /// u16 variable- the destination port to us.
    /// Output: a Result<(), String>- if the sending went well.
    pub fn notify_client(ip_client: IP, port: u16, data: AttackData) -> Result<(), String> {
        let mut stream = TcpStream::connect(build_connection_str_tcp(ip_client.copy(), port).clone()).expect("Failed to connect to server");
        let data_to_send = data.get_data_str_json();

        stream.write_all(data_to_send.as_bytes()).expect("Failed to send data!");

        return Ok(());
    }

}