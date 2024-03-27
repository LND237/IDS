using System;
using WpfApp1.Models.Ip;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Client
{
    internal class Communicator
    {
        private const int PORT_NUM = 50001;
        private readonly IP ip;

        public Communicator()
        {
            this.ip = new IP("127.0.0.1");
        }

        public AttackData GetMessageServer()
        {

            return new AttackData();
        }

    }
}
