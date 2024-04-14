using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    public class AttackLog 
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
}
