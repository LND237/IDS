using Client;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Client
{
    public class MongoDBAttackLogger
    {
        private readonly IMongoDatabase _database;
        private readonly MAC _clientMac;

        /// <summary>
        /// c'tor for the class.
        /// </summary>
        /// <param name="username"> the username for the connection</param>
        /// <param name="password"> the password for the connection</param>
        /// <param name="databaseName"> the databaseName for the connection</param>
        /// <param name="address"> the name of the collection</param>
        /// the
        public MongoDBAttackLogger(string username, string password, string databaseName, MAC address)
        {
            //Preparing connection uri
            string encodedPassword = Uri.EscapeDataString(password);//encode password
            string connectionUri = "mongodb+srv://" + username + ":" + encodedPassword + "@ideproject.jii1z04.mongodb.net/?retryWrites=true&w=majority&appName=ideProject";
            
            var settings = MongoClientSettings.FromConnectionString(connectionUri);
            // Set the ServerApi field of the settings object to set the version of the Stable API on the client
            settings.ServerApi = new ServerApi(ServerApiVersion.V1);
            
            var client = new MongoClient(settings);
            _database = client.GetDatabase(databaseName);
            this._clientMac = address.Copy();
        }

        /// <summary>
        /// gets all the attacks of the client
        /// </summary>
        /// <returns>all the attacks of the client</returns>
        public List<AttackLog> getAllAttacks()
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());

            var filter = Builders<AttackLog>.Filter.Empty; // Get all documents
            var attackLogs = collection.Find(filter).ToList();

            return GetFormattedLogs(attackLogs);
        }
        /// <summary>
        /// get the last N attacks of the client
        /// </summary>
        /// <param name="count"> the amount of the last attacks to get</param>
        /// <returns>list of attackLogs</returns>
        public List<AttackLog> GetLastAttacks(int count)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());

            var sort = Builders<AttackLog>.Sort.Descending(log => log.Time); // Sort by Time (descending)
            var attackLogs = collection.Find(Builders<AttackLog>.Filter.Empty)
                                             .Sort(sort)
                                             .Limit(count)
                                             .ToList();

            return GetFormattedLogs(attackLogs);
        }

        /// <summary>
        /// get the attacks that happend within the last N minutes
        /// </summary>
        /// <param name="minutes"> the amount of minutes</param>
        /// <returns>list of the attacks</returns>
        public List<AttackLog> GetAttacksInLastNMinutes(int minutes)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());
            DateTime startTimeUtc = DateTime.UtcNow.Subtract(TimeSpan.FromMinutes(minutes));

            var filter = Builders<AttackLog>.Filter.Where(log => DateTime.Parse(log.Time) > startTimeUtc.ToUniversalTime());
            var attackLogs = collection.Find(filter).ToList();

            return GetFormattedLogs(attackLogs);
        }

        public List<AttackLog> GetAttacksBeforeDate(DateTime endDate)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());

            var filter = Builders<AttackLog>.Filter.Where(log => DateTime.Parse(log.Time) < endDate);
            var attackLogs = collection.Find(filter).ToList();

            return GetFormattedLogs(attackLogs);
        }

        /// <summary>
        /// gets all the attacks with a specific attacker ip
        /// </summary>
        /// <param name="attackerIp">the ip of the attacker</param>
        /// <returns>list of attacks</returns>
        public List<AttackLog> GetAttackerIpAttacks(string attackerIp)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());
            var filter = Builders<AttackLog>.Filter.Eq(log => log.AttackerIp, attackerIp);

            var attackLogs = collection.Find(filter).ToList();
            return GetFormattedLogs(attackLogs);
        }


        /// <summary>
        /// the function gets a list of all the attackers ip's (no duplicated values).
        /// </summary>
        /// <returns>The ips.</returns>
        public List<IP> GetAllAttackerIps()
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());

            var attackerIpsStrings = collection.Distinct<string>("AttackerIp", Builders<AttackLog>.Filter.Empty).ToList();

            List<IP> ips = new List<IP>();

            foreach(string ipStr  in attackerIpsStrings)
            {
                ips.Add(new IP(ipStr));
            }
            return ips;
        }

        public List<AttackLog> GetFormattedLogs(List<AttackLog> attackLogs)
        {
            const string FULL_NAME_DBD = "Drive By Download";
            
            //Going over the logs and editing them
            foreach (AttackLog log in attackLogs)
            {
                string date = log.Time;
                // Split the string by whitespaces
                string[] parts = date.Split(':');

                // Extract the desired format (first two parts)
                log.Time = string.Join(":", parts.Take(2));

                if (log.AttackName.Equals(FULL_NAME_DBD))
                {
                    log.AttackName = "DBD";
                }

                if (log.AttackerIp.Equals(IP.BROADCAST_IP))
                {
                    log.AttackerIp = "Unkown";
                }
            }
            return attackLogs;
        }


    }

}
