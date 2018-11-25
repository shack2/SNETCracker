using AxMSTSCLib;
using MSTSCLib;
using SNETCracker.Model;
using System;
using System.Timers;
using Tools;

namespace MyRDP
{
    public class RdpClient : AxMsRdpClient4NotSafeForScripting
    {
        private Server server= null;
        public delegate void OnResponseDelegate(ResponseType type, Server server);
        public event OnResponseDelegate OnResponse;
        public System.Timers.Timer timeOutLog = new System.Timers.Timer();
        public ResponseType response =ResponseType.Connecting;
        public RdpClient(Server cserver)
        {  
            this.server = cserver;
            this.timeOutLog.Interval = server.timeout * 1000;
            this.timeOutLog.Elapsed += TimeOut;
            this.OnConnected += Rdp_OnConnected;
            this.OnLoginComplete += Rdp_OnLoginComplete;
            this.OnLogonError += Rdp_OnLogonError;
            this.OnFatalError += Rdp_OnFatalError;
            this.OnDisconnected += Rdp_OnDisconnected;
            this.OnAuthenticationWarningDisplayed += Rdp_OnAuthenticationWarningDisplayed;
            this.OnAuthenticationWarningDismissed += Rdp_OnAuthenticationWarningDismissed;
           

        }


        public object Password { get; internal set; }

        private void Finished() {
            OnResponse(ResponseType.Finished, server);
        }
        private void TimeOut(object sender, ElapsedEventArgs e) {
            this.timeOutLog.Stop();
            Finished();
        }

        public delegate void deConnect(string ip, int port, string user, string pass);
        public  void Connect(string ip,int port,string user,string pass)
        {
            try
            {
                this.timeOutLog.Start();
                this.AdvancedSettings.Compress = 1;
                this.Height =1;
                this.Width = 1;
                this.Password = pass;
                this.ColorDepth =4 ;
                this.Server = ip;
                this.UserName = user;
                this.AdvancedSettings4.EnableMouse = 0;
                this.AdvancedSettings4.EnableWindowsKey = 0;
                this.AdvancedSettings4.RDPPort = port;
                IMsTscNonScriptable secured = (IMsTscNonScriptable)this.GetOcx();
                secured.ClearTextPassword = pass;
                this.Connect();
             
            }
            catch (Exception e)
            {
                timeOutLog.Stop();
                throw e;
            }
        }
        private void Rdp_OnDisconnected(object sender, IMsTscAxEvents_OnDisconnectedEvent e)
        {
            Finished();
        }  

        private void Rdp_OnFatalError(object sender, IMsTscAxEvents_OnFatalErrorEvent e)
        {
            Finished();
        }

        private void Rdp_OnLogonError(object sender, IMsTscAxEvents_OnLogonErrorEvent e)
        {
            Finished();

        }

        private void Rdp_OnLoginComplete(object sender, EventArgs e)
        {
            this.server.isSuccess = true;
            Finished();
        }

        private void Rdp_OnConnected(object sender, EventArgs e)
        {
            this.server.isConnected = true;
            
        }

        private void Rdp_OnAuthenticationWarningDismissed(object sender, EventArgs e)
        {
            Finished();

        }

        private void Rdp_OnAuthenticationWarningDisplayed(object sender, EventArgs e)
        {
            Finished();

        }
    }
}
