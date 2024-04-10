using System;
using System.Linq;
using System.Net;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Client
{
    public class IP
    {
        public string ip { get; set; }
        public static readonly string BROADCAST_IP = "255.255.255.255";
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
            this.ip = ip;
        }
        /// <summary>
        /// default c'tor, set ip to broadcast
        /// </summary>
        public IP()
        {
            this.ip = BROADCAST_IP;
        }
        /// <summary>
        /// get the ip as string
        /// </summary>
        /// <returns>the ip as string</returns>
        public string GetIP()
        {
            return this.ip;
        }
        /// <summary>
        /// the function validates Ip address
        /// </summary>
        /// <param name="ipAddress">the ip to validate</param>
        /// <returns>true if valid, otherwise false</returns>
        public bool IsValidIp(string ipAddress)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(ipAddress))
                {
                    return false;
                }

                string[] splitValues = ipAddress.Split('.');
                if (splitValues.Length != 4)
                {
                    return false;
                }

                byte tempForParsing;

                return splitValues.All(r => byte.TryParse(r, out tempForParsing));
            }
            catch { return false; }
        }
    }
}


