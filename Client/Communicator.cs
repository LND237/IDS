using System;
using WpfApp1.Models.Ip;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;

namespace Client
{
    internal class Communicator
    {
        private const int PORT_NUM = 50001;
        private const int MAX_SIZE_BUFFER = 1024;
        private readonly IP ip;

        /// <summary>
        /// Constructor of class Communicator.
        /// </summary>
        public Communicator()
        {
            this.ip = new IP("127.0.0.1");
        }

        /// <summary>
        /// The function gets the message from the server,
        /// then converts it to an AttackData object.
        /// </summary>
        /// <returns>The data from the server.</returns>
        public AttackData GetMessageServer()
        {
            string dataReceived = "";
            // Specify the IP address and port on which the server will listen
            IPAddress ipAddress = IPAddress.Parse(ip.GetIP()); // Listen on localhost

            // Create a TCP listener
            TcpListener listener = new TcpListener(ipAddress, PORT_NUM);

            // Start listening for incoming connection requests
            listener.Start();

            // Accept the pending client connection
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine("Client connected.");

            // Get the network stream for reading
            NetworkStream stream = client.GetStream();
            dataReceived = ReadClientData(stream);

            // Close the client connection
            client.Close();

            listener.Stop();

            return AttackData.Deserialize(dataReceived);
        }

        /// <summary>
        /// The function reads the data from the client's stream.
        /// </summary>
        /// <param name="stream">The stream of data to read from.</param>
        /// <returns>The data as a string.</returns>
        private static string ReadClientData(NetworkStream stream)
        {
            string dataReceived = "";

            // Buffer for storing incoming data
            byte[] buffer = new byte[MAX_SIZE_BUFFER];
            int bytesRead;

            // Read data from the client
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                // Convert the data received into a string
                dataReceived = Encoding.UTF8.GetString(buffer, 0, bytesRead);
            }

            return dataReceived;
        }

    }
}
