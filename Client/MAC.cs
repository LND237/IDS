using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Client
{
    public class MAC
    {
        private readonly string _mac;

        /// <summary>
        /// Default constructor of class MAC.
        /// </summary>
        public MAC()
        {
            this._mac = "ff:ff:ff:ff:ff:ff";
        }

        /// <summary>
        /// Constructor of class MAC.
        /// </summary>
        /// <param name="mac">The mac address.</param>
        /// <exception cref="ArgumentException"> The given mac was invalid.</exception>
        public MAC(string mac) 
        {
            if (!isMacValid(mac))
            {
                throw new ArgumentException("Invalid MAC Address");
            }
            this._mac = mac;
        }

        /// <summary>
        /// The function copies the mac address.
        /// </summary>
        /// <returns>The copied MAC.</returns>
        public MAC Copy()
        {
            return new MAC(this._mac);
        }

        /// <summary>
        /// The function gets the address.
        /// </summary>
        /// <returns>The address.</returns>
        public string GetAddress() { return this._mac; }

        /// <summary>
        /// The function checks if a string is a valid
        /// mac address.
        /// </summary>
        /// <param name="mac">The string to check.</param>
        /// <returns>If it is valid or not.</returns>
        private static bool isMacValid(string mac)
        {
            Regex r = new Regex("^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{2}){5}[0-9a-fA-F]{2}$");

            return r.IsMatch(mac);
        }
    }
}
