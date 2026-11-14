using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using Xunit;

namespace Sveto4.Tests
{
    /// <summary>In-memory Task Scheduler: never touches the system.</summary>
    internal sealed class FakeScheduler : ITaskScheduler
    {
        public readonly Dictionary<string, string> Tasks = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string GetTaskXml(string name) => Tasks.TryGetValue(name, out var xml) ? xml : null;
        public void Register(string name, string xml) => Tasks[name] = xml;
        public void Delete(string name) => Tasks.Remove(name);
    }

    public class AutostartTests
    {
        private const string Exe = @"D:\Apps\Sveto4\sveto4.exe";
        private const string User = @"PC\User";

        private readonly FakeScheduler scheduler = new FakeScheduler();
        private readonly HashSet<string> files = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Exe };

        private Autostart Create(string exe = Exe) => new Autostart(scheduler, exe, User, files.Contains);

        private static string Value(string xml, string name) =>
            XDocument.Parse(xml).Descendants().First(e => e.Name.LocalName == name).Value;

        [Fact]
        public void Xml_LogonOfCurrentUser_HighestPrivileges_NoArguments()
        {
            var xml = Autostart.BuildTaskXml(Exe, User);

            Assert.Equal(User, Value(xml, "UserId"));
            Assert.Equal("HighestAvailable", Value(xml, "RunLevel"));
            Assert.Equal("InteractiveToken", Value(xml, "LogonType"));
            Assert.Equal("PT0S", Value(xml, "ExecutionTimeLimit"));      // no 3-day limit
            Assert.Equal("false", Value(xml, "DisallowStartIfOnBatteries"));
            Assert.Equal("false", Value(xml, "StopIfGoingOnBatteries"));
            Assert.Equal("\"" + Exe + "\"", Value(xml, "Command"));
            Assert.Equal(@"D:\Apps\Sveto4", Value(xml, "WorkingDirectory"));
            Assert.DoesNotContain(XDocument.Parse(xml).Descendants(), e => e.Name.LocalName == "Arguments");
            Assert.Single(XDocument.Parse(xml).Descendants(), e => e.Name.LocalName == "LogonTrigger");
        }

        [Fact]
        public void Xml_EscapesSpecialCharacters()
        {
            const string exe = @"C:\R&D 'x'\sveto4.exe";
            Assert.Equal(exe, Autostart.ParseCommand(Autostart.BuildTaskXml(exe, User)));
        }

        [Theory]
        [InlineData("<Task><Actions><Exec><Command>C:\\a\\b.exe</Command></Exec></Actions></Task>", @"C:\a\b.exe")]
        [InlineData("<Task><Actions><Exec><Command> \"C:\\a b\\c.exe\" </Command></Exec></Actions></Task>", @"C:\a b\c.exe")]
        [InlineData("<Task><Actions></Actions></Task>", null)]
        [InlineData("not xml", null)]
        public void ParseCommand(string xml, string expected) =>
            Assert.Equal(expected, Autostart.ParseCommand(xml));

        [Fact]
        public void NoTask_Off() => Assert.Equal(AutostartStatus.Off, Create().GetStatus());

        [Fact]
        public void Enable_Then_Disable()
        {
            var a = Create();
            a.Enable();
            Assert.Equal(AutostartStatus.On, a.GetStatus());
            Assert.True(scheduler.Tasks.ContainsKey("Sveto4"));

            a.Disable();
            Assert.Equal(AutostartStatus.Off, a.GetStatus());
            a.Disable(); // no task: no error
        }

        [Fact]
        public void PathComparison_IgnoresCase()
        {
            Create(Exe.ToUpperInvariant()).Enable();
            Assert.Equal(AutostartStatus.On, Create().GetStatus());
        }

        [Fact]
        public void OtherExistingCopy_NotTakenOver()
        {
            const string other = @"D:\Dev\Sveto4\dist\sveto4.exe";
            files.Add(other);
            Create(other).Enable();

            var a = Create();
            Assert.Equal(AutostartStatus.OtherCopy, a.GetStatus());
            Assert.False(a.RepairIfBroken());
            Assert.Equal(other, Autostart.ParseCommand(scheduler.Tasks["Sveto4"]));
        }

        [Fact]
        public void MovedExe_TaskRepaired()
        {
            Create(@"D:\Old\sveto4.exe").Enable();  // file no longer exists

            var a = Create();
            Assert.Equal(AutostartStatus.Broken, a.GetStatus());
            Assert.True(a.RepairIfBroken());
            Assert.Equal(AutostartStatus.On, a.GetStatus());
        }

        [Fact]
        public void Repair_DoesNotCreateTaskWhenOff()
        {
            Assert.False(Create().RepairIfBroken());
            Assert.Empty(scheduler.Tasks);
        }

        [Theory]
        [InlineData(AutostartStatus.On, ExeExposure.Folder, "\t⚠ Writable folder")]
        [InlineData(AutostartStatus.On, ExeExposure.Exe, "\t⚠ Writable exe")]
        [InlineData(AutostartStatus.On, ExeExposure.None, "")]
        [InlineData(AutostartStatus.Off, ExeExposure.Folder, "")]       // nothing runs elevated yet
        [InlineData(AutostartStatus.OtherCopy, ExeExposure.Folder, "\tother copy")]
        [InlineData(AutostartStatus.Broken, ExeExposure.None, "\t⚠ Not found")]
        public void MenuSuffix(object status, object exposure, string expected) =>
            Assert.Equal(expected, Autostart.MenuSuffix((AutostartStatus)status, (ExeExposure)exposure));

        [Fact]
        public void CheckExe_WritableFolder_NotReset()
        {
            var resets = 0;
            Assert.Equal(ExeExposure.Folder,
                Autostart.CheckExe(Exe, dir => false, file => false, file => { resets++; return true; }));
            Assert.Equal(0, resets); // someone else's folder is never changed
        }

        [Fact]
        public void CheckExe_AdminOnly_NotReset()
        {
            var resets = 0;
            Assert.Equal(ExeExposure.None,
                Autostart.CheckExe(Exe, dir => true, file => true, file => { resets++; return true; }));
            Assert.Equal(0, resets);
        }

        [Fact]
        public void CheckExe_WritableExe_ResetToFolderPermissions()
        {
            var adminOnly = false;
            string reset = null;
            Assert.Equal(ExeExposure.None,
                Autostart.CheckExe(Exe, dir => true, file => adminOnly, file => { reset = file; adminOnly = true; return true; }));
            Assert.Equal(Exe, reset);
        }

        [Fact]
        public void CheckExe_ResetFailed_Exe()
        {
            Assert.Equal(ExeExposure.Exe, Autostart.CheckExe(Exe, dir => true, file => false, file => false));
            // Reset reported success, but the file is still exposed.
            Assert.Equal(ExeExposure.Exe, Autostart.CheckExe(Exe, dir => true, file => false, file => true));
        }
    }
}
