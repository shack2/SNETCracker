using System;
using System.Data;
using System.Data.SqlClient;
using Tools;

namespace SNETCracker.Model
{
    class CrackSQLServer : CrackService
    {
        public CrackSQLServer() {

        }

        public override Server creack(String ip, int port,String username,String password,int timeOut) {

            SqlConnection conn = null;
            Server server= new Server();
                try {
                    conn = new SqlConnection("Data Source="+ip+","+port+";Uid=" + username + ";Password=" + password + ";Connect Timeout=" + timeOut);
                    conn.Open();
                    server.isSuccess= ConnectionState.Open.Equals(conn.State);
                    if (server.isSuccess)
                    {
                        server.banner = conn.ServerVersion;
                    }
            } catch (Exception e)
            {
                if (e.Message.IndexOf("TCP Provider, error: 0") != -1|| e.Message.IndexOf("连接超时") != -1)
                {
                    throw new TimeoutException(e.Message);
                }
                
                else {
                    throw e;
                }

             }
                finally
                {
                    if (conn != null)
                    {
                        conn.Close();
                    }
                }
            return server;
        }
    }
}
