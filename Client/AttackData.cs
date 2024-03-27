using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Client
{
    internal class AttackData
    {
        [JsonPropertyName("ip")]
        private string ip;
        [JsonPropertyName("name")]
        private string name;
        [JsonPropertyName("date")]
        private string date;

        public AttackData(string ip, string name, string date)
        {
            this.ip = ip;
            this.name = name;
            this.date = date;
        }

        public string GetIP()
        {
            return ip;
        }

        public string GetName() 
        {
            return name;
        }

        public string GetDate() 
        {
            return date;
        }
    }
}
