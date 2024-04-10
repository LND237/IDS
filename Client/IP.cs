using System;
using System.Linq;
using System.Net;

namespace Client
{
    public class IP
    {
        private readonly string _ip;
        /// <summary>
        /// c'tor for ip class
        /// </summary>
        /// <param name="ip"> the ip to set</param>
        /// <exception cref="InvalidOperationException">if the ip is not valid</exception>
        public IP(string ip)
        {

            if (IsValidIp(ip) == false)
            {
                throw new Exception("Invalid IP!");
            }
            this._ip = ip;
        }
        /// <summary>
        /// default c'tor, set ip to broadcast
        /// </summary>
        public IP()
        {
            this._ip = "255.255.255.255";
        }
        /// <summary>
        /// get the ip as string
        /// </summary>
        /// <returns>the ip as string</returns>
        public string GetIP()
        {
            return this._ip;
        }
        /// <summary>
        /// the function validates Ip address
        /// </summary>
        /// <param name="ipAddress">the ip to validate</param>
        /// <returns>true if valid, otherwise false</returns>
        public bool IsValidIp(string ipAddress)
        {
            // Try parsing as a valid IP address (encompasses both IPv4 and IPv6)
            if (IPAddress.TryParse(ipAddress, out _))
            {
                return true;
            }

            // Additional IPv4 specific validation (in case TryParse succeeded with an IPv4)
            if (ipAddress.Contains("."))
            {
                var parts = ipAddress.Split('.');
                if (parts.Length == 4)
                {
                    return parts.All(part => byte.TryParse(part, out byte value) && value <= 255);
                }
            }

            return false; // If none of the conditions were met
        }
    }
}


