using System;
using System.Collections.Generic;
using System.Linq;

namespace Sveto4.Tests
{
    /// <summary>Fake processes, files and adapters for <see cref="KillSwitch"/>; nothing touches the system.</summary>
    internal static class TestEnv
    {
        public const string HappDir = @"C:\Program Files\FlyFrogLLC\Happ";

        public static readonly string[] HappFiles =
        {
            HappDir + @"\Happ.exe",
            HappDir + @"\happd.exe",
            HappDir + @"\core\xray.exe",
            HappDir + @"\tun\sing-box.exe",
            HappDir + @"\unins000.exe",
            HappDir + @"\vc_redist.x64.exe",
        };

        public static ClientEnvironment Create(
            Func<IEnumerable<ProcessEntry>> processes = null,
            IEnumerable<string> files = null,
            List<AdapterInfo> adapters = null)
        {
            var fileList = (files ?? new string[0]).ToList();
            var adapterList = adapters ?? new List<AdapterInfo>();
            return new ClientEnvironment
            {
                Processes = processes ?? (() => new ProcessEntry[0]),
                DirectoryExists = dir => fileList.Any(f => f.StartsWith(dir + @"\", StringComparison.OrdinalIgnoreCase)),
                ListExe = dir => fileList.Where(f => f.StartsWith(dir + @"\", StringComparison.OrdinalIgnoreCase)),
                Adapters = () => adapterList.ToList(),
            };
        }

        public static AdapterInfo Adapter(string name, string description = "", bool up = true) =>
            new AdapterInfo(name, description, up, false);
    }
}
