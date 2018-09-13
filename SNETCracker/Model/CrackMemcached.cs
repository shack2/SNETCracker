using Enyim.Caching;
using Enyim.Caching.Configuration;
using Enyim.Caching.Memcached;
using System;
using System.Net;
using Tools;

namespace SNETCracker.Model
{
    class CrackMemcached : CrackService
    {
        public CrackMemcached() {

        }

        public override Server creack(String ip, int port,String username,String password,int timeOut) {
         
                MemcachedClient conn = null;
            Server server = new Server();
            
                try
                {
                    MemcachedClientConfiguration memConfig = new MemcachedClientConfiguration();
      
                    IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Parse(ip), port);
                    //配置文件 - ip  
                    memConfig.Servers.Add(ipEndPoint);
                    //配置文件 - 协议  
                    memConfig.Protocol = MemcachedProtocol.Binary;
                    //配置文件-权限，如果使用了免密码功能，则无需设置userName和password  
                    memConfig.Authentication.Type = typeof(PlainTextAuthenticator);
                    memConfig.Authentication.Parameters["zone"] = "";
                    if (!"空".Equals(password)) {
                        memConfig.Authentication.Parameters["userName"] = username;
                        memConfig.Authentication.Parameters["password"] = password;
                    }
                    //下面请根据实例的最大连接数进行设置  
                    memConfig.SocketPool.MinPoolSize = 1;
                    memConfig.SocketPool.MaxPoolSize = 1;
                    memConfig.SocketPool.ConnectionTimeout = TimeSpan.FromSeconds(timeOut);
                    memConfig.SocketPool.ReceiveTimeout = TimeSpan.FromSeconds(timeOut);
                    memConfig.SocketPool.DeadTimeout = TimeSpan.FromSeconds(timeOut);
                    conn = new MemcachedClient(memConfig);
               
                    server.isSuccess = true;
                }
                catch (Exception e)
                {
                    throw e;
                }
                finally {
                    if (conn != null) {
                        conn.Dispose();
                    }
                }
            return server;
        }
    }
}
