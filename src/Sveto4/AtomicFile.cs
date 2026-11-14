using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Sveto4
{
    /// <summary>
    /// Writes a file through a temporary file in the same folder that then replaces it, so a crash or
    /// power loss leaves either the old or the new contents, never a truncated file.
    /// </summary>
    internal static class AtomicFile
    {
        private static readonly object Sync = new object();
        private static readonly Encoding Utf8 = new UTF8Encoding(false); // same as File.WriteAllText

        public static void WriteAllText(string path, string contents)
        {
            lock (Sync)
            {
                var temp = path + ".tmp";
                if (File.Exists(temp)) File.Delete(temp); // left over from an interrupted write
                // The temporary file is created in the target folder, so it gets the folder's permissions.
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                using (var writer = new StreamWriter(stream, Utf8))
                    writer.Write(contents);

                if (File.Exists(path)) File.Replace(temp, path, null, true);
                else File.Move(temp, path);
            }
        }

        public static void WriteAllLines(string path, IEnumerable<string> lines)
        {
            var text = new StringBuilder();
            foreach (var line in lines) text.AppendLine(line);
            WriteAllText(path, text.ToString());
        }
    }
}
