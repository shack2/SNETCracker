using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Collections;
using System.Collections.Concurrent;
using System.Threading;

namespace Tools
{
    public static class FileTool
    {
        public static List<string> readAllDic(String dic)
        {
            List<string> fs = new List<string>();
            try
            {
                DirectoryInfo din = new DirectoryInfo(dic);
                FileInfo[] files = din.GetFiles();
                foreach (FileInfo f in files)
                {
                    fs.Add(f.Name);
                }
            }
            catch (Exception re)
            {
                log(dic + "读取错误！" + re.Message);
            }
            return fs;
        }
        //读取单个字典文件（文件编码为UTF-8）
        public static HashSet<string> readFileToList(String path)
        {

            HashSet<string> list = new HashSet<string>();
            FileStream fs_dir = null;
            StreamReader reader = null;
            try
            {
                fs_dir = new FileStream(path, FileMode.Open, FileAccess.Read);

                reader = new StreamReader(fs_dir);

                string lineStr;

                while ((lineStr = reader.ReadLine()) != null)
                {
                    if (!lineStr.Equals("")&& !list.Contains(lineStr))
                    {
                        list.Add(lineStr);
                    }
                }
            }
            catch (Exception e)
            {
                log("读取文件列表发生异常！" + e.Message);
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                }
                if (fs_dir != null)
                {
                    fs_dir.Close();
                }
            }
            return list;
        }

        //读取文件
        public static String readFileToString(String path)
        {
            return File.ReadAllText(path);
        }
        public static object c = "";
        public static void AppendLogToFile(String path, String log)
        {
            lock (c)
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.AppendAllText(path, log+"\r\n");
            }
        }

        public static void WriteStringToFile(String path, String line)
        {
            File.WriteAllText(path, line);
        }
        public static void WriteStringToFile(String path, HashSet<String> dics)
        {
            string[] lines = new string[dics.Count];
            dics.CopyTo(lines);
            dics.Clear();
            File.WriteAllLines(path, lines);
        }
        /// <summary>诊断日志缓冲队列：认证异常/端口扫描高频调用时避免每次 lock+磁盘写导致线程串行化；
        /// 按目标文件路径分组，2 秒批量落盘</summary>
        private static readonly ConcurrentQueue<KeyValuePair<string, string>> logBuffer = new ConcurrentQueue<KeyValuePair<string, string>>();
        private static readonly object logTimerLock = new object();
        private static Timer logFlushTimer;

        /// <summary>缓冲写入运行日志（logs/runlog-yyyy-MM-dd.log，自动加时间戳）</summary>
        public static void log(String log)
        {
            EnqueueLog(AppContext.BaseDirectory + "/logs/runlog-" + DateTime.Now.ToString("yyyy-MM-dd") + ".log",
                DateTime.Now.ToString("HH:mm:ss.fff") + " " + log);
        }

        /// <summary>缓冲写入指定日志文件（端口扫描结果等高频路径用，原文写入不加时间戳）</summary>
        public static void logToFile(String path, String line)
        {
            EnqueueLog(path, line);
        }

        private static void EnqueueLog(string path, string line)
        {
            logBuffer.Enqueue(new KeyValuePair<string, string>(path, line));
            // 懒启动 2 秒批量落盘
            if (logFlushTimer == null)
            {
                lock (logTimerLock)
                {
                    if (logFlushTimer == null)
                    {
                        logFlushTimer = new Timer(_ => FlushLogBuffer(), null, 2000, 2000);
                    }
                }
            }
        }

        private static void FlushLogBuffer()
        {
            if (logBuffer.IsEmpty)
            {
                return;
            }
            // 按目标文件分组，同一路径合并为一次磁盘写
            var groups = new Dictionary<string, StringBuilder>();
            while (logBuffer.TryDequeue(out KeyValuePair<string, string> item))
            {
                if (!groups.TryGetValue(item.Key, out StringBuilder sb))
                {
                    sb = new StringBuilder();
                    groups[item.Key] = sb;
                }
                sb.AppendLine(item.Value);
            }
            foreach (var kv in groups)
            {
                AppendLogToFile(kv.Key, kv.Value.ToString().TrimEnd());
            }
        }
        public static String getDomainByString(String weburl)
        {
            try
            {
                if (!weburl.StartsWith("http://"))
                {
                    weburl = "http://" + weburl;
                }
                Uri u = new Uri(weburl);

                if (u.Port == 80)
                {
                    return u.Scheme + "://" + u.Host + "/" + u.LocalPath;
                }
                return u.Scheme + "://" + u.Host + ":" + u.Port + "/";

            }
            catch (Exception e)
            {
                log(e.Message);
            }
            return "";
        }
    }
}