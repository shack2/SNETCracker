using System;
using System.IO;
using System.Net.Http;
using System.Threading;

namespace Tools
{
    public static class Tool
    {
        // 静态复用 HttpClient：避免每次新建连接/TLS 会话；AOT 安全
        private static readonly HttpClient http = new HttpClient();
        // getHtml 语义不允许自动跳转（与原 AllowAutoRedirect=false 一致）；下载更新包允许跳转（GitHub 302）
        private static readonly HttpClient httpNoRedirect = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });

        public static void HttpDownloadFile(string url, string path)
        {
            using (Stream responseStream = http.GetStreamAsync(url).GetAwaiter().GetResult())
            using (Stream stream = new FileStream(path, FileMode.Create))
            {
                responseStream.CopyTo(stream);
            }
        }

        public static String getHtml(String url, int timeout)
        {
            try
            {
                using (var cts = new CancellationTokenSource(timeout * 1000))
                using (HttpResponseMessage resp = httpNoRedirect.GetAsync(url, cts.Token).GetAwaiter().GetResult())
                {
                    return resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                }
            }
            catch (Exception e)
            {
                FileTool.log(e.Message);
                return "";
            }
        }
    }
}
