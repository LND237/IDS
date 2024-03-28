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
    public class Communicator
    {
        private const int MAX_SIZE_BUFFER = 1024;
        private readonly TcpListener listener;

        /// <summary>
        /// Constructor of communicator.
        /// </summary>
        /// <param name="port">The number of port to listen.</param>
        public Communicator(int port)
        {
            IP ip = new IP("127.0.0.1");
            this.listener = CreateListener(ip, port);
        }

        /// <summary>
        /// The function gets the message from the server,
        /// then converts it to an AttackData object.
        /// </summary>
        /// <returns>The data from the server.</returns>
        public AttackData GetMessageServer()
        {
            string dataReceived = "";

            // Accept the pending client connection
            TcpClient client = this.listener.AcceptTcpClient();

            // Get the network stream for reading
            NetworkStream stream = client.GetStream();
            dataReceived = ReadClientData(stream);

            // Close the client connection
            client.Close();

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
                try
                {
                    // Trying to convert the data received into a string
                    dataReceived += Encoding.UTF8.GetString(buffer, 0, bytesRead);
                }
                catch //UTF Encoding did not work 
                {
                    dataReceived = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                }
            }

            return dataReceived;
        }

        /// <summary>
        /// The function creates a listener.
        /// </summary>
        /// <param name="ip">The ip to listen from.</param>
        /// <param name="port">The number of port to listen.</param>
        /// <returns>The listener.</returns>
        private static TcpListener CreateListener(IP ip, int port)
        {
            // Specify the IP address and port on which the server will listen
            IPAddress ipAddress = IPAddress.Parse(ip.GetIP()); // Listen on localhost

            // Create a TCP listener
            TcpListener listener = new TcpListener(ipAddress, port);

            return listener;
        }

        /// <summary>
        /// The function makes the listener to start listening.
        /// </summary>
        public void StartListening()
        {
            this.listener.Start();
        }

        /// <summary>
        /// The function makes the listener to stop listening.
        /// </summary>
        public void StopListening() 
        {
            this.listener.Stop();
        }

    }
}
