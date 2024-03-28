using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;


namespace Client
{
    public class AttackData
    {
        [JsonProperty("ip")]
        private string ip;
        [JsonProperty("name")]
        private string name;
        [JsonProperty("date")]
        private string date;

        /// <summary>
        /// Constructor of class AttackData.
        /// </summary>
        /// <param name="ip">The ip which did the attack.</param>
        /// <param name="name">The name of the attack.</param>
        /// <param name="date">The date of the attack.</param>
        public AttackData(string ip, string name, string date)
        {
            this.ip = ip;
            this.name = name;
            this.date = date;
        }

        /// <summary>
        /// The function gets the ip.
        /// </summary>
        /// <returns>The ip.</returns>
        public string GetIP()
        {
            return ip;
        }

        /// <summary>
        /// The function gets the name of the attack.
        /// </summary>
        /// <returns>The name.</returns>
        public string GetName() 
        {
            return name;
        }

        /// <summary>
        /// The function gets the date of the attack.
        /// </summary>
        /// <returns>The date.</returns>
        public string GetDate() 
        {
            return date;
        }

        /// <summary>
        /// The function deserialize a string to
        /// an AttackData object.
        /// </summary>
        /// <param name="json">The string with the data.</param>
        /// <returns>The data as an AttackData object.</returns>
        /// <exception cref="Exception">In case deserialization fails.</exception>
        public static AttackData Deserialize(string json)
        {
            AttackData data = JsonConvert.DeserializeObject<AttackData>(json);
            if (data == null) 
            {
                throw new ArgumentNullException();
            }
            return data;
        }

        /// <summary>
        /// The function makes a string from the data.
        /// </summary>
        /// <returns>The string.</returns>
        public override string ToString()
        {
            return $"IP: {this.ip}, Name: {this.name}, date: {this.date}";
        }
    }
}
