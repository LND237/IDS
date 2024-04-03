using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class LocalAddress
    {

        /// <summary>
        /// The function gets the local ip of this machine's interface.
        /// </summary>
        /// <returns>The local ip.</returns>
        /// <exception cref="Exception">No ip was found.</exception>
        public static IP GetLocalIP()
        {
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

            //Going over the ips in the list
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork) //the ip is ipv4
                {
                    return new IP(ip.ToString());
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");

        }

        /// <summary>
        /// The function finds the local mac of the internet interface.
        /// </summary>
        /// <returns> The mac address.</returns>
        /// <exception cref="Exception">No mac address was found.</exception>
        public static MAC GetLocalMAC()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                // Only consider Ethernet network interfaces
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&
                    nic.OperationalStatus == OperationalStatus.Up)
                {
                    string macAddr = nic.GetPhysicalAddress().ToString();
                    string formattedMacAddr = FormatMAC(macAddr);
                    return new MAC(formattedMacAddr);
                }
            }
            throw new Exception("No mac address for was found");
        }

        /// <summary>
        /// The function makes an mac address to be
        /// in the right format.
        /// </summary>
        /// <param name="mac"> The address to format.</param>
        /// <returns>The formatted address.</returns>
        private static string FormatMAC(string mac)
        {
            string formattedMac = "";
            const string COLON = ":";

            //Going over the characters of the address
            for(int i = 1; i < mac.Length + 1;i++) 
            {
                formattedMac += mac[i - 1].ToString();
                if (i % 2 == 0)
                {
                    formattedMac += COLON;
                }
            }

            return formattedMac.Substring(0, formattedMac.Length - 1); //removing the last COLON
        }
    }
}
