using System;
using System.IO;

namespace Sveto4
{
    /// <summary>
    /// Minimal file logger. Errors go here instead of message boxes.
    /// Location: %LOCALAPPDATA%\Sveto4\sveto4.log (rotated at 1 MB).
    /// </summary>
    internal static class Log
    {
        private const long MaxSize = 1024 * 1024;
        private static readonly object Sync = new object();

        public static readonly string FilePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sveto4", "sveto4.log");

        /// <summary>Only the app itself writes the log: unit tests (another entry assembly) must not pollute it.</summary>
        private static readonly bool Enabled = string.Equals(
            System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name, "sveto4", StringComparison.OrdinalIgnoreCase);

        public static void Info(string message) => Write("INFO ", message);

        public static void Error(Exception ex, string context = null) =>
            Write("ERROR", (context != null ? context + ": " : "") + (ex?.ToString() ?? "unknown error"));

        private static void Write(string level, string message)
        {
            if (!Enabled) return;
            try
            {
                lock (Sync)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(FilePath));
                    var file = new FileInfo(FilePath);
                    if (file.Exists && file.Length > MaxSize)
                    {
                        var old = FilePath + ".old";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(FilePath, old);
                    }
                    File.AppendAllText(FilePath, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level} {message}{Environment.NewLine}");
                }
            }
            catch
            {
                // Logging must never break the app.
            }
        }
    }
}
