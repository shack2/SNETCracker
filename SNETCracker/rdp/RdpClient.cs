using AxMSTSCLib;
using MSTSCLib;
using SNETCracker.Model;
using System;
using System.Timers;
using Tools;

namespace MyRDP
{
    public class RdpClient : AxMsRdpClient7NotSafeForScripting
    {
        public Server server = null;
        public String name = "";
        public delegate void OnResponseDelegate(ResponseType type,RdpClient rdp, ref Server server);
        public event OnResponseDelegate OnResponse;

        public ResponseType response = ResponseType.Connecting;
        public RdpClient()
        {
           
            this.OnConnected += Rdp_OnConnected;
            this.OnLoginComplete += Rdp_OnLoginComplete;
            this.OnFatalError += Rdp_OnFatalError;
            this.OnLogonError += Rdp_OnLoginError;
            this.OnDisconnected += Rdp_OnDisconnected;
            this.OnAuthenticationWarningDisplayed += Rdp_OnAuthenticationWarningDisplayed;
            this.OnAuthenticationWarningDismissed += Rdp_OnAuthenticationWarningDismissed;
            this.OnWarning += Rdp_OnWaring;
        }

        public object Password { get; internal set; }

        private void Finished()
        {
            OnResponse(ResponseType.Finished,this,ref server);
            
        }
        private void TimeOut(object sender, ElapsedEventArgs e)
        {
            Finished();
        }
        public void ConnectServer(Server server)
        {
            try
            {

                this.server = server;
                this.Height = 1;
                this.Width = 1;
                this.Server = server.ip;
                this.ColorDepth = 8;

                this.AdvancedSettings.Compress = 1;
                this.UserName = server.username;
                this.AdvancedSettings7.RDPPort = server.port;
                this.AdvancedSettings7.ClearTextPassword = server.password;
                this.AdvancedSettings7.EnableCredSspSupport = true;
                this.AdvancedSettings7.ConnectToAdministerServer = true;
                this.AdvancedSettings7.EnableMouse = 0;
                this.AdvancedSettings7.EnableWindowsKey = 0;
                this.AdvancedSettings7.EncryptionEnabled = 0;
                this.AdvancedSettings7.AuthenticationLevel = 0;
                this.AdvancedSettings7.RedirectClipboard = false;
                this.AdvancedSettings7.overallConnectionTimeout = server.timeout;
                this.AdvancedSettings7.BitmapPeristence = 1;
                this.AdvancedSettings7.DisplayConnectionBar = false;
                this.AdvancedSettings7.RedirectDrives = false;
                this.AdvancedSettings7.PinConnectionBar = false;
                this.AdvancedSettings7.RedirectPorts = false;
                this.AdvancedSettings7.RedirectPrinters = false;
                this.AdvancedSettings7.RedirectSmartCards = true;
                
                IMsRdpClientNonScriptable5 sc = (IMsRdpClientNonScriptable5)this.GetOcx();
                sc.AllowPromptingForCredentials = false;
                sc.AllowCredentialSaving = false;
                sc.WarnAboutSendingCredentials = false;
                sc.WarnAboutClipboardRedirection = false;
                sc.ShowRedirectionWarningDialog = false;
                sc.PromptForCredentials = false;
                sc.PromptForCredsOnClient = false;
                sc.WarnAboutPrinterRedirection = false;
                sc.WarnAboutDirectXRedirection = false;
                this.Connect();

            }
            catch (Exception e)
            {
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
            this.server.banner =this.Domain;
            
            Finished();
        }

        private void Rdp_OnLoginError(object sender, IMsTscAxEvents_OnLogonErrorEvent e)
        {
            this.server.isSuccess = false;
            if (e.lError != -2) {
                Finished();
            }
            
        }

        private void Rdp_OnWaring(object sender, IMsTscAxEvents_OnWarningEvent e)
        {
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