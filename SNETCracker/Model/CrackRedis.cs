using StackExchange.Redis;
using System;
using Tools;
namespace SNETCracker.Model
{
    class CrackRedis : CrackService
    {
        public CrackRedis() {

        }

        public override Server creack(String ip, int port,String username,String password,int timeOut) {
            Server server = new Server();
            String connectionStr = ip + ":" + port + ",connectTimeout=" + timeOut*1000;       
            if (!password.Equals("空")) {
                connectionStr+=",password="+password;
            }
            ConnectionMultiplexer redis = null;
            try
            {
                redis = ConnectionMultiplexer.Connect(connectionStr);
                if (redis.IsConnected)
                {
                    server.isSuccess = true;
                    server.banner = redis.ClientName;
                }
            }
            catch (Exception e)
            {
                throw e;
            }
            finally {
                if (redis != null) {
                    redis.Close();
                }
            }
            return server;
        }
    }
}
