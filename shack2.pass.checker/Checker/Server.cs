using System;

namespace SNETCracker.Checker
{
    /// <summary>单次认证的结果：成功与否、Banner、耗时。仅保留实际使用的字段。</summary>
    public class Server
    {
        public bool isSuccess = false;
        public string banner = "";
        public string ip = "";
        public int port = 0;
        public string username = "";
        public string password = "";
        public long userTime = 0;
    }
}
