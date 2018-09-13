using MongoDB.Driver;
using System;
using Tools;

namespace SNETCracker.Model
{
    class CrackMongoDB : CrackService
    {
        public CrackMongoDB() {

        }

        public override Server creack(String ip, int port,String username,String password,int timeOut) {
                MongoServer conn = null;
                Server server= new Server();
                try
                {
                    String connectionstr = "mongodb://"+username+":"+password+"@" + ip + ":" + port;
                    if (password.Equals("空")) {
                        connectionstr = "mongodb://" + ip + ":" + port;
                    }
                    MongoServerSettings config = MongoServerSettings.FromUrl(MongoUrl.Create(connectionstr));
                    //最大闲置时间
                    
                    config.MaxConnectionIdleTime = TimeSpan.FromSeconds(timeOut);
                    //最大存活时间
                    config.MaxConnectionLifeTime = TimeSpan.FromSeconds(timeOut);
                    //链接时间
                    config.ConnectTimeout = TimeSpan.FromSeconds(timeOut);
                    //socket超时时间
                    config.SocketTimeout = TimeSpan.FromSeconds(timeOut);
                    conn = new MongoServer(config);
                    conn.Connect();
                    if (conn.State.Equals(MongoServerState.Connected)) {
                        server.isSuccess = true;
                        server.banner = conn.BuildInfo.VersionString;
                    }
                }
                catch (Exception e)
                {
                    throw e;
                }
                finally {
                    if (conn != null) {
                        conn.Disconnect();
                    }
                }
            return server;
        }
    }
}
