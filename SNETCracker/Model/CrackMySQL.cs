using MySql.Data.MySqlClient;
using System;
using System.Data;
using System.Data.SqlClient;
using System.Threading;
using Tools;

namespace SNETCracker.Model
{
    class CrackMySQL : CrackService
    {
        public CrackMySQL()
        {

        }
       
        public override Server creack(String ip, int port, String username, String password, int timeOut)
        {
            MySqlConnection conn = new MySqlConnection();
            MySqlConnectionStringBuilder ms = new MySqlConnectionStringBuilder();
            Server server = new Server();

            try
            {
                if (password.Equals("空"))
                {
                    password = "";
                }
                conn.ConnectionString = "server=" + ip + ";user id=" + username + ";password=" + password + ";pooling=false;ConnectionTimeout=" + timeOut;

                conn.Open();
                
                server.isSuccess = ConnectionState.Open.Equals(conn.State);
                if (server.isSuccess)
                {
                    server.banner = conn.ServerVersion;
                }
            }
            catch (Exception e)
            {
                if (e.Message.IndexOf("not allowed to") != -1 || e.Message.IndexOf("many connection") != -1)
                {
                    throw new IPBreakException(ip + port);
                }
                else if (e.Message.IndexOf("user not exist") != -1)
                {
                    throw new IPUserBreakException(ip + port + username);
                }
                else if (e.Message.IndexOf("没有正确答复") != -1||e.Message.IndexOf("Timeout in IO operation")!=-1||e.Message.IndexOf("Reading from")!=-1||e.Message.IndexOf("无法从传输连接中读取数据") != -1 || e.Message.IndexOf("Unable to") != -1)
                {
                    new TimeoutException(e.Message);
                }
                else if (e.Message.IndexOf("using password: ") != -1)
                {
                    return server;
                }
                else
                {
                    throw e;
                }
            }
            finally
            {
                conn.Close();
            }
            return server;
        }
    }
}
