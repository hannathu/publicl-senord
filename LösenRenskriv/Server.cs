using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LösenRenskriv
{
    public class Server
    {
        public byte[] EncryptedVault { get; set; }
        public byte[] IV { get; set; }

        public string Path = "server.json";
    }
}
