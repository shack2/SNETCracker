using Npgsql;
using System;
using System.Data;
using Tools;

namespace SNETCracker.Model
{
    class CrackPostgreSQL : CrackService
    {
        public CrackPostgreSQL()
        {

        }
        public override Server creack(String ip, int port,String username,String password,int timeOut) {

                NpgsqlConnection conn = null;
            Server server = new Server();
                try
                {
                    NpgsqlConnectionStringBuilder sb = new NpgsqlConnectionStringBuilder();
                   
                    conn = new NpgsqlConnection("Server="+ip+";Port="+port+";User Id="+username+";Password="+password+ ";Database=postgres;Timeout=" + timeOut+";ConnectionLifeTime = " + timeOut);
                    conn.Open();
                    server.isSuccess= ConnectionState.Open.Equals(conn.State);
                    if (server.isSuccess)
                    {
                        server.banner = conn.ServerVersion;
                    }
            }
            catch (Exception e)
                {
                    throw e;
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
