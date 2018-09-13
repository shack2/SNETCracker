using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace Tools
{
    class FileTool
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
        public static HashSet<String> readFileToList(String path)
        {

            HashSet<String> list = new HashSet<String>();
            FileStream fs_dir = null;
            StreamReader reader = null;
            try
            {
                fs_dir = new FileStream(path, FileMode.Open, FileAccess.Read);

                reader = new StreamReader(fs_dir);

                String lineStr;

                while ((lineStr = reader.ReadLine()) != null)
                {
                    if (!lineStr.Equals(""))
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
        public static void log(String log)
        {
            AppendLogToFile(AppDomain.CurrentDomain.BaseDirectory + "/log.txt", log);

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