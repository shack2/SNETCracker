using System;
using System.IO;
using System.Net;
using System.Text;

namespace Tools
{
    class Tool
    {
        public static void HttpDownloadFile(string url, string path)
        {
            // 设置参数
            HttpWebRequest request = WebRequest.Create(url) as HttpWebRequest;

            //发送请求并获取相应回应数据
            HttpWebResponse response = request.GetResponse() as HttpWebResponse;
            //直到request.GetResponse()程序才开始向目标网页发送Post请求
            Stream responseStream = response.GetResponseStream();

            //创建本地文件写入流
            Stream stream = new FileStream(path, FileMode.Create);

            byte[] bArr = new byte[1024];
            int size = responseStream.Read(bArr, 0, (int)bArr.Length);
            while (size > 0)
            {
                stream.Write(bArr, 0, size);
                size = responseStream.Read(bArr, 0, (int)bArr.Length);
            }
            stream.Close();
            responseStream.Close();
        }
        public static String getHtml(String url, int timeout)
        {
            String html = "";
            HttpWebResponse response = null;
            StreamReader sr = null;
            HttpWebRequest request = null;
            try
            {

                //设置模拟http访问参数
                Uri uri = new Uri(url);
                request = (HttpWebRequest)WebRequest.Create(uri);
                request.Accept = "*/*";
                request.Method = "GET";
                request.Timeout = timeout * 1000;
                request.AllowAutoRedirect = false;
                response = (HttpWebResponse)request.GetResponse();
                sr = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
                //读取服务器端返回的消息 
                html = sr.ReadToEnd();
            }
            catch (Exception e)
            {
                FileTool.log(e.Message);
            }
            finally
            {
                if (sr != null)
                {
                    sr.Close();
                }
                if (response != null)
                {
                    response.Close();
                }
                if (request != null)
                {
                    request.Abort();
                }
            }
            return html;
        }
    }
}
