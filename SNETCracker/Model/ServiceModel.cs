using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SNETCracker.Model
{
    class ServiceModel
    {
        public String Name="";
        public String Port = "";
        public String DicUserNamePath="";
        public String DicPasswordPath="";
        public HashSet<String> ListUserName=new HashSet<string>();
        public HashSet<String> ListPassword = new HashSet<string>();
    }
}
