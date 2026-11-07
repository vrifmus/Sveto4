using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Sveto4
{
    internal enum AutostartStatus
    {
        Unknown,
        Off,
        /// <summary>The task starts this exe.</summary>
        On,
        /// <summary>The task starts another existing copy of the program.</summary>
        OtherCopy,
        /// <summary>The task points to a file that no longer exists.</summary>
        Broken,
    }

    /// <summary>Access to Windows Task Scheduler (replaced by a fake in tests).</summary>
    internal interface ITaskScheduler
    {
        /// <summary>Task definition XML, or null if there is no such task.</summary>
        string GetTaskXml(string name);
        void Register(string name, string xml);
        void Delete(string name);
    }

    /// <summary>
    /// "Start with Windows": a Task Scheduler task run at logon of the current user with
    /// highest privileges, so the elevated app starts without a UAC prompt.
    /// </summary>
    internal sealed class Autostart
    {
        public const string TaskName = "Sveto4";
        private const string Ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        private readonly ITaskScheduler scheduler;
        private readonly string exePath;
        private readonly string userId;
        private readonly Func<string, bool> fileExists;

        public Autostart(ITaskScheduler scheduler, string exePath, string userId, Func<string, bool> fileExists)
        {
            this.scheduler = scheduler;
            this.exePath = exePath;
            this.userId = userId;
            this.fileExists = fileExists;
        }

        public static Autostart CreateDefault() =>
            new Autostart(new ComTaskScheduler(), Assembly.GetExecutingAssembly().Location,
                          WindowsIdentity.GetCurrent().Name, File.Exists);

        public AutostartStatus GetStatus()
        {
            var xml = scheduler.GetTaskXml(TaskName);
            if (xml == null) return AutostartStatus.Off;
            var command = ParseCommand(xml);
            if (command != null && SamePath(command, exePath)) return AutostartStatus.On;
            return command != null && fileExists(command) ? AutostartStatus.OtherCopy : AutostartStatus.Broken;
        }

        public void Enable() => scheduler.Register(TaskName, BuildTaskXml(exePath, userId));

        public void Disable()
        {
            if (scheduler.GetTaskXml(TaskName) != null) scheduler.Delete(TaskName);
        }

        /// <summary>
        /// Called at startup: if the exe was moved (the task points to a missing file), points the task here.
        /// Another existing copy is left alone, so running a test build does not take over autostart.
        /// </summary>
        public bool RepairIfBroken()
        {
            if (GetStatus() != AutostartStatus.Broken) return false;
            Enable();
            return true;
        }

        // ---------- Pure helpers ----------

        public static string BuildTaskXml(string exePath, string userId)
        {
            XNamespace ns = Ns;
            var doc = new XDocument(
                new XElement(ns + "Task", new XAttribute("version", "1.2"),
                    new XElement(ns + "RegistrationInfo",
                        new XElement(ns + "Description", "Sveto4 VPN kill switch (tray)")),
                    new XElement(ns + "Triggers",
                        new XElement(ns + "LogonTrigger",
                            new XElement(ns + "Enabled", "true"),
                            new XElement(ns + "UserId", userId))),
                    new XElement(ns + "Principals",
                        new XElement(ns + "Principal", new XAttribute("id", "Author"),
                            new XElement(ns + "UserId", userId),
                            new XElement(ns + "LogonType", "InteractiveToken"),
                            new XElement(ns + "RunLevel", "HighestAvailable"))),
                    new XElement(ns + "Settings",
                        new XElement(ns + "MultipleInstancesPolicy", "IgnoreNew"),
                        new XElement(ns + "DisallowStartIfOnBatteries", "false"),
                        new XElement(ns + "StopIfGoingOnBatteries", "false"),
                        new XElement(ns + "AllowHardTerminate", "true"),
                        new XElement(ns + "StartWhenAvailable", "false"),
                        new XElement(ns + "RunOnlyIfNetworkAvailable", "false"),
                        new XElement(ns + "IdleSettings",
                            new XElement(ns + "StopOnIdleEnd", "false"),
                            new XElement(ns + "RestartOnIdle", "false")),
                        new XElement(ns + "AllowStartOnDemand", "true"),
                        new XElement(ns + "Enabled", "true"),
                        new XElement(ns + "Hidden", "false"),
                        new XElement(ns + "RunOnlyIfIdle", "false"),
                        new XElement(ns + "WakeToRun", "false"),
                        new XElement(ns + "ExecutionTimeLimit", "PT0S"),
                        new XElement(ns + "Priority", "4")),
                    new XElement(ns + "Actions", new XAttribute("Context", "Author"),
                        new XElement(ns + "Exec",
                            new XElement(ns + "Command", "\"" + exePath + "\""),
                            new XElement(ns + "WorkingDirectory", Path.GetDirectoryName(exePath))))));

            var sb = new StringBuilder();
            using (var w = XmlWriter.Create(sb, new XmlWriterSettings { Indent = true, Encoding = Encoding.Unicode }))
                doc.Save(w);
            return sb.ToString();
        }

        /// <summary>Path from the first Exec action, without quotes; null if absent or unreadable.</summary>
        public static string ParseCommand(string xml)
        {
            try
            {
                var command = XDocument.Parse(xml).Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "Command" && e.Parent?.Name.LocalName == "Exec");
                var value = command?.Value.Trim().Trim('"');
                return string.IsNullOrEmpty(value) ? null : Environment.ExpandEnvironmentVariables(value);
            }
            catch (XmlException)
            {
                return null;
            }
        }

        public static bool SamePath(string a, string b)
        {
            try
            {
                return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    /// <summary>Task Scheduler through the "Schedule.Service" COM API.</summary>
    internal sealed class ComTaskScheduler : ITaskScheduler
    {
        private const int CreateOrUpdate = 6;
        private const int LogonInteractiveToken = 3;
        private const int FileNotFound = unchecked((int)0x80070002);

        private static dynamic RootFolder()
        {
            dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
            service.Connect();
            return service.GetFolder("\\");
        }

        public string GetTaskXml(string name)
        {
            try
            {
                return RootFolder().GetTask(name).Xml;
            }
            catch (Exception ex) when (ex is FileNotFoundException || (ex as COMException)?.ErrorCode == FileNotFound)
            {
                return null;
            }
        }

        public void Register(string name, string xml) =>
            RootFolder().RegisterTask(name, xml, CreateOrUpdate, null, null, LogonInteractiveToken, null);

        public void Delete(string name) => RootFolder().DeleteTask(name, 0);
    }
}
