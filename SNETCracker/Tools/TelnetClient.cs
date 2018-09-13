using System;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Tools
{
    public class TelnetClient : IDisposable
    {
        private TcpClient tcpSocket;
        private int TimeoutMs = 100;

        public bool IsConnected
        {
            get
            {
                return tcpSocket.Connected;
            }
        }

        public TelnetClient(string hostname, int port)
        {
            tcpSocket = new TcpClient(hostname, port);
        }

        ~TelnetClient()
        {
            Dispose(false);
        }

        public string Login(string username, string password, int loginTimeoutMs)
        {
            int oldTimeoutMs = TimeoutMs;
            TimeoutMs = loginTimeoutMs;

            string s = Read();
            if (!s.TrimEnd().EndsWith(":"))
            {
                throw new Exception("Failed to connect : no login prompt");
            }

            WriteLine(username);

            s += Read();
            if (!s.TrimEnd().EndsWith(":"))
            {
                throw new Exception("Failed to connect : no password prompt");
            }

            WriteLine(password);

            s += Read();

            TimeoutMs = oldTimeoutMs;

            return s;
        }

        public void WriteLine(string cmd)
        {
            Write(cmd + "\n");
        }

        public void Write(string cmd)
        {
            if (!tcpSocket.Connected)
            {
                return;
            }

            byte[] buf = ASCIIEncoding.ASCII.GetBytes(cmd.Replace("\0xFF", "\0xFF\0xFF"));
            tcpSocket.GetStream().Write(buf, 0, buf.Length);
        }

        public string Read()
        {
            if (!tcpSocket.Connected)
            {
                return null;
            }

            var sb = new StringBuilder();
            do
            {
                ParseTelnet(sb);
                Thread.Sleep(TimeoutMs);

            } while (tcpSocket.Available > 0);

            return sb.ToString();
        }

        private void ParseTelnet(StringBuilder sb)
        {
            while (tcpSocket.Available > 0)
            {
                int input = tcpSocket.GetStream().ReadByte();
                switch (input)
                {
                    case -1:
                        break;

                    case (int)Verbs.Iac:
                        // interpret as command
                        int inputVerb = tcpSocket.GetStream().ReadByte();
                        if (inputVerb == -1)
                        {
                            break;
                        }

                        switch (inputVerb)
                        {
                            case (int)Verbs.Iac:
                                // literal IAC = 255 escaped, so append char 255 to string
                                sb.Append(inputVerb);
                                break;

                            case (int)Verbs.Do:
                            case (int)Verbs.Dont:
                            case (int)Verbs.Will:
                            case (int)Verbs.Wont:
                                // reply to all commands with "WONT", unless it is SGA (suppres go ahead)
                                int inputoption = tcpSocket.GetStream().ReadByte();
                                if (inputoption == -1)
                                {
                                    break;
                                }

                                tcpSocket.GetStream().WriteByte((byte)Verbs.Iac);

                                if (inputoption == (int)Options.Sga)
                                {
                                    tcpSocket.GetStream().WriteByte(inputVerb == (int)Verbs.Do ? (byte)Verbs.Will : (byte)Verbs.Do);
                                }
                                else
                                {
                                    tcpSocket.GetStream().WriteByte(inputVerb == (int)Verbs.Do ? (byte)Verbs.Wont : (byte)Verbs.Dont);
                                }

                                tcpSocket.GetStream().WriteByte((byte)inputoption);
                                break;
                        }

                        break;

                    default:
                        sb.Append((char)input);
                        break;
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (tcpSocket != null)
                {
                    ((IDisposable)tcpSocket).Dispose();
                    tcpSocket = null;
                }
            }
        }


        #region Private Enums

        enum Verbs
        {
            Will = 251,
            Wont = 252,
            Do = 253,
            Dont = 254,
            Iac = 255
        }

        enum Options
        {
            Sga = 3
        }

        #endregion
    }
}