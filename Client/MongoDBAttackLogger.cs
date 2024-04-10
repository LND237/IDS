using Client;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
namespace Client
{

    internal class MongoDBAttackLogger
    {
        private readonly IMongoDatabase _database;
        private readonly MAC _clientMac;
        private readonly string connectionString;
        public class AttackLog //attacks data  struct
        {
            [BsonId]
            public ObjectId Id { get; set; }

            [BsonElement("ip")]
            public required string AttackerIp { get; set; }

            [BsonElement("name")]
            public required string AttackName { get; set; }

            [BsonElement("date")]
            public string Time { get; set; }
        }
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
            string encodedPassword = Uri.EscapeDataString(password);//encode password

            //connectionString = "mongodb+srv://" + username + ":" + encodedPassword + "@" + databaseName + ".mongodb.net/?retryWrites=true&w=majority";
            //connectionString = "mongodb+srv://bsyl:" + encodedPassword + "@ideproject.jii1z04.mongodb.net/?retryWrites=true&w=majority&appName=ideProject";
            //var client = new MongoClient(connectionString);
            //_database = client.GetDatabase(databaseName);
            //this._clientMac = address.Copy();
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

            return attackLogs;
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

            return attackLogs;
        }

        /// <summary>
        /// get the attacks that happend within the last N minutes
        /// </summary>
        /// <param name="minutes"> the amount of minutes</param>
        /// <returns>list of the attacks</returns>
        public List<AttackLog> GetAttacksInLastNMinutes(int minutes)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());
            var cutoffTime = DateTime.Now.Subtract(TimeSpan.FromMinutes(minutes));

            var filter = Builders<AttackLog>.Filter.Gt(log => DateTime.Parse(log.Time), cutoffTime);
            var attackLogs = collection.Find(filter).ToList();

            return attackLogs;
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
            return attackLogs;
        }


        /// the function gets a list of all the attackers ip's (no duplicated values)
        public List<string> GetAllAttackerIpsAsync()
        {
            var collection = _database.GetCollection<AttackLog>(this._clientMac.GetAddress());

            var attackerIps = collection.Distinct<string>("AttackerIp", Builders<AttackLog>.Filter.Empty).ToList();

            return attackerIps;
        }


    }

}
