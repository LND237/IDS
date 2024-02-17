using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
using MongoDB.Driver.Core.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using WpfApp1.Models.Ip;
namespace WpfApp1.Models.MongoDB
{
    
    internal class MongoDBAttackLogger
    {
        private readonly IMongoDatabase _database;
        private readonly IP _clientIp;
        private readonly string connectionString;
        public class AttackLog //attacks data  struct
        {
            [BsonId]
            public ObjectId Id { get; set; }

            public required string AttackerIp { get; set; }
            public required string AttackName { get; set; }
            public DateTime Time { get; set; }
        }
        /// <summary>
        /// c'tor for the class.
        /// </summary>
        /// <param name="username"> the username for the connection</param>
        /// <param name="password"> the password for the connection</param>
        /// <param name="databaseName"> the databaseName for the connection</param>
        /// the
        public MongoDBAttackLogger(string username,string password,string databaseName, string ip)
        {
            string encodedPassword = Uri.EscapeDataString(password);//encode passowrd

            connectionString = "mongodb+srv://" + username + ":" + encodedPassword + "@" + databaseName + ".mongodb.net/?retryWrites=true&w=majority";
            var client = new MongoClient(connectionString);
            _database = client.GetDatabase(databaseName);
            this._clientIp = new IP(ip);
        }

        /// <summary>
        /// gets all the attacks of the client
        /// </summary>
        /// <returns>all the attacks of the client</returns>
        public async Task<List<AttackLog>> getAllAttacks()
        {
            var collection = _database.GetCollection<AttackLog>(this._clientIp.GetIP());

            var filter = Builders<AttackLog>.Filter.Empty; // Get all documents
            var attackLogs = await collection.Find(filter).ToListAsync();

            return attackLogs;
        }
        /// <summary>
        /// get the last N attacks of the client
        /// </summary>
        /// <param name="count"> the amount of the last attacks to get</param>
        /// <returns>list of attackLogs</returns>
        public async Task<List<AttackLog>> GetLastAttacks(int count)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientIp.GetIP());

            var sort = Builders<AttackLog>.Sort.Descending(log => log.Time); // Sort by Time (descending)
            var attackLogs = await collection.Find(Builders<AttackLog>.Filter.Empty)
                                             .Sort(sort)
                                             .Limit(count)
                                             .ToListAsync();

            return attackLogs;
        }

        /// <summary>
        /// get the attacks that happend within the last N minutes
        /// </summary>
        /// <param name="minutes"> the amount of minutes</param>
        /// <returns>list of the attacks</returns>
        public async Task<List<AttackLog>> GetAttacksInLastNMinutes(int minutes)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientIp.GetIP());
            var cutoffTime = DateTime.Now.Subtract(TimeSpan.FromMinutes(minutes));

            var filter = Builders<AttackLog>.Filter.Gt(log => log.Time, cutoffTime);
            var attackLogs = await collection.Find(filter).ToListAsync();

            return attackLogs;
        }

        /// <summary>
        /// gets all the attacks with a specific attacker ip
        /// </summary>
        /// <param name="attackerIp">the ip of the attacker</param>
        /// <returns>list of attacks</returns>
        public async Task<List<AttackLog>> GetAttackerIpAttacks(string attackerIp)
        {
            var collection = _database.GetCollection<AttackLog>(this._clientIp.GetIP());
            var filter = Builders<AttackLog>.Filter.Eq(log => log.AttackerIp, attackerIp);

            var attackLogs = await collection.Find(filter).ToListAsync();
            return attackLogs;
        }

        
        /// the function gets a list of all the attackers ip's (no duplicated values)
        public async Task<List<string>> GetAllAttackerIpsAsync()
        {
            var collection = _database.GetCollection<AttackLog>(this._clientIp.GetIP());

            var attackerIps = await collection.Distinct<string>("AttackerIp", Builders<AttackLog>.Filter.Empty)
                                              .ToListAsync();
    
            return attackerIps;
        }


    }

}
