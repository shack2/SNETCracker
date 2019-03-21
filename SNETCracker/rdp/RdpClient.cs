using AxMSTSCLib;
using MSTSCLib;
using SNETCracker.Model;
using System;
using System.Timers;
using Tools;

namespace MyRDP
{
    public class RdpClient : AxMsRdpClient4
    {
        private Server server = null;
        public delegate void OnResponseDelegate(ResponseType type, Server server);
        public event OnResponseDelegate OnResponse;
        public System.Timers.Timer timeOutLog = new System.Timers.Timer();
        public ResponseType response = ResponseType.Connecting;
        public RdpClient(Server cserver)
        {
            this.server = cserver;
            this.timeOutLog.Interval = server.timeout * 1000;
            this.timeOutLog.Elapsed += TimeOut;
            this.OnConnected += Rdp_OnConnected;
            this.OnLoginComplete += Rdp_OnLoginComplete;
            this.OnFatalError += Rdp_OnFatalError;
            this.OnDisconnected += Rdp_OnDisconnected;
            this.OnAuthenticationWarningDisplayed += Rdp_OnAuthenticationWarningDisplayed;
            this.OnAuthenticationWarningDismissed += Rdp_OnAuthenticationWarningDismissed;
            this.OnWarning += Rdp_OnWaring;
        }


        public object Password { get; internal set; }

        private void Finished()
        {
            if (this.IsDisposed == false)
            {
                this.Disconnect();
            }
            OnResponse(ResponseType.Finished, server);
        }
        private void TimeOut(object sender, ElapsedEventArgs e)
        {
            this.timeOutLog.Stop();
            Finished();
        }

        public delegate void deConnect(string ip, int port, string user, string pass);
        public void Connect(string ip, int port, string user, string pass)
        {
            try
            {
                this.timeOutLog.Start();
                this.AdvancedSettings.Compress = 1;
                this.Height = 1;
                this.Width = 1;
                this.Password = pass;
                this.ColorDepth = 1;
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
            FileTool.log("RDP_OnFatalError:" + e.errorCode);
        }

        private void Rdp_OnLoginComplete(object sender, EventArgs e)
        {
            this.server.isSuccess = true;
            this.server.banner = this.ProductVersion;
            Finished();
        }

        private void Rdp_OnWaring(object sender, IMsTscAxEvents_OnWarningEvent e)
        {

            Finished();
            FileTool.log("RDP_OnWaring:" + e.warningCode);
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