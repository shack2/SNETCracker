using System;

namespace SPasswordCheckerV2.Data
{
    public class CheckResult
    {
        public CheckResult()
        {

        }

        public CheckResult(int Index, string IP, string ServiceName, int Port, string Username, string Password, string Banner, long UseTime)
        {
            this.Index = Index;
            this.IP = IP;
            this.ServiceName = ServiceName;
            this.Port = Port;
            this.Username = Username;
            this.Password = Password;
            this.Banner = Banner;
            this.UseTime = UseTime;
        }

        public int Index { get; set; }
        public string IP { get; set; }
        public string ServiceName { get; set; }
        public int Port { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Banner { get; set; }
        public long UseTime { get; set; }
    }
}
