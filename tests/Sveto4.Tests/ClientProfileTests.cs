using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    public class ClientProfileTests
    {
        private static readonly ClientProfile Happ = ClientProfiles.Happ;

        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly FakeStore store = new FakeStore();
        private readonly List<AdapterInfo> adapters = new List<AdapterInfo>
        {
            TestEnv.Adapter("Wi-Fi"),
            TestEnv.Adapter("happ-xray", "Happ Tunnel"),
        };
        private List<ProcessEntry> processes = new List<ProcessEntry>();

        private KillSwitch Create(IEnumerable<string> files = null) =>
            new KillSwitch(fw, TestEnv.Create(() => processes, files ?? TestEnv.HappFiles, adapters), store);

        private KsState Read(KillSwitch ks)
        {
            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
            ks.ReadAdapters(s);
            return s;
        }

        private string[] RuleNames() => fw.Rules.Select(r => r.Name).OrderBy(n => n).ToArray();

        // ---------- Matching ----------

        [Theory]
        [InlineData("happ-xray", "Happ Tunnel", true)]
        [InlineData("happ-sing-box", "", true)]          // by name prefix
        [InlineData("Ethernet 3", "Happ Tunnel", true)]  // by description
        [InlineData("Wi-Fi", "Killer Wi-Fi", false)]
        [InlineData("chappy", "", false)]               // substring is not enough anymore
        public void MatchesAdapter(string name, string description, bool expected) =>
            Assert.Equal(expected, Happ.MatchesAdapter(name, description));

        [Theory]
        [InlineData(@"C:\Happ\unins000.exe", true)]
        [InlineData(@"C:\Happ\vc_redist.x64.exe", true)]
        [InlineData(@"C:\Happ\core\xray.exe", false)]
        [InlineData(@"C:\Happ\Happ.exe", false)]
        public void ExcludesInstallers(string path, bool excluded) =>
            Assert.Equal(excluded, Happ.IsExcluded(path));

        [Fact]
        public void InstallDir_FromRunningProcess()
        {
            var env = TestEnv.Create(() => new[]
            {
                new ProcessEntry { Name = "chrome.exe", ExePath = @"C:\Chrome\chrome.exe" },
                new ProcessEntry { Name = "happd.exe", ExePath = @"D:\Apps\Happ\happd.exe" },
            });
            Assert.Equal(@"D:\Apps\Happ", ClientProfiles.ResolveInstallDir(Happ, env));
        }

        [Fact]
        public void InstallDir_DefaultWhenNotRunning()
        {
            var expected = System.Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\FlyFrogLLC\Happ");
            var env = TestEnv.Create(files: new[] { expected + @"\Happ.exe" });
            Assert.Equal(expected, ClientProfiles.ResolveInstallDir(Happ, env));
        }

        [Fact]
        public void InstallDir_NullWhenNotInstalled() =>
            Assert.Null(ClientProfiles.ResolveInstallDir(Happ, TestEnv.Create()));

        [Fact]
        public void AppRuleNames_DuplicatesGetSuffix()
        {
            var names = KillSwitch.AppRuleNames(Happ, new[] { @"C:\a\x.exe", @"C:\b\x.exe", @"C:\c\y.exe" })
                .Select(p => p.Key).ToArray();
            Assert.Equal(new[] { "KS-App-happ-x", "KS-App-happ-x-2", "KS-App-happ-y" }, names);
        }

        // ---------- Enable / disable ----------

        [Fact]
        public void Enable_AllowsAllExecutablesAndAdapters()
        {
            Create(TestEnv.HappFiles.Select(f => f.Replace(TestEnv.HappDir, ExpandedDefault)))
                .EnableClient(Happ);

            Assert.Equal(new[] { "KS-Allow-happ-xray", "KS-App-happ-Happ", "KS-App-happ-happd", "KS-App-happ-sing-box", "KS-App-happ-xray" },
                         RuleNames());
            Assert.EndsWith(@"\tun\sing-box.exe", fw.Find("KS-App-happ-sing-box").ApplicationName); // core not running yet
            Assert.True(store.Clients["happ"]);
        }

        private static string ExpandedDefault =>
            System.Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\FlyFrogLLC\Happ");

        [Fact]
        public void Enable_UsesFolderOfRunningClient()
        {
            processes = new List<ProcessEntry> { new ProcessEntry { Name = "Happ.exe", ExePath = TestEnv.HappDir + @"\Happ.exe" } };
            Create().EnableClient(Happ);

            Assert.Equal(TestEnv.HappDir + @"\core\xray.exe", fw.Find("KS-App-happ-xray").ApplicationName);
            Assert.DoesNotContain(fw.Rules, r => r.Name.Contains("unins") || r.Name.Contains("vc_redist"));
        }

        [Fact]
        public void Enable_NotInstalled_OnlyAdapters()
        {
            Create(new string[0]).EnableClient(Happ);
            Assert.Equal(new[] { "KS-Allow-happ-xray" }, RuleNames());
        }

        [Fact]
        public void Disable_RemovesClientRulesOnly()
        {
            processes = new List<ProcessEntry> { new ProcessEntry { Name = "Happ.exe", ExePath = TestEnv.HappDir + @"\Happ.exe" } };
            var ks = Create();
            ks.SelectInterface("Wi-Fi");
            ks.EnableClient(Happ);

            ks.DisableClient(Happ, Read(ks));

            Assert.Equal(new[] { "KS-Allow-Wi-Fi" }, RuleNames());
            Assert.False(store.Clients["happ"]);
        }

        [Fact]
        public void State_ReportsEnabledAndInstallDir()
        {
            processes = new List<ProcessEntry> { new ProcessEntry { Name = "Happ.exe", ExePath = TestEnv.HappDir + @"\Happ.exe" } };
            var ks = Create();
            ks.EnableClient(Happ);

            var s = Read(ks);
            var c = Assert.Single(s.Clients);
            Assert.True(c.Enabled);
            Assert.Equal(TestEnv.HappDir, c.InstallDir);
            Assert.Equal(Happ, s.ManagingClient("happ-xray"));
            Assert.Null(s.ManagingClient("Wi-Fi"));
        }

        [Fact]
        public void Migration_EnabledWhenOldAppRulesExist()
        {
            fw.Rules.Add(new RuleSpec { Name = "KS-App-happ-xray" });
            Assert.True(Read(Create()).IsClientEnabled("happ"));
        }

        [Fact]
        public void Migration_StoredSettingWins()
        {
            fw.Rules.Add(new RuleSpec { Name = "KS-App-happ-xray" });
            store.Clients["happ"] = false;
            Assert.False(Read(Create()).IsClientEnabled("happ"));
        }

        // ---------- Sync after adapter changes ----------

        [Fact]
        public void CoreSwitch_NewAdapterAdded_OldRemoved()
        {
            processes = new List<ProcessEntry> { new ProcessEntry { Name = "Happ.exe", ExePath = TestEnv.HappDir + @"\Happ.exe" } };
            var ks = Create();
            ks.EnableClient(Happ);

            // Happ switches core: happ-xray disappears, happ-sing-box appears.
            adapters.RemoveAll(a => a.Name == "happ-xray");
            adapters.Add(TestEnv.Adapter("happ-sing-box", "Happ Tunnel"));

            var s = Read(ks);
            Assert.True(KillSwitch.NeedsClientSync(s));
            ks.SyncClients(s);

            var after = Read(ks);
            Assert.Equal(new[] { "happ-sing-box" }, after.Interfaces.ToArray());
            Assert.False(KillSwitch.NeedsClientSync(after));
        }

        [Fact]
        public void Sync_KeepsManuallySelectedAdapters()
        {
            processes = new List<ProcessEntry> { new ProcessEntry { Name = "Happ.exe", ExePath = TestEnv.HappDir + @"\Happ.exe" } };
            var ks = Create();
            ks.SelectInterface("Ethernet"); // not present, but not a Happ adapter
            ks.EnableClient(Happ);

            ks.SyncClients(Read(ks));

            Assert.Contains("Ethernet", Read(ks).Interfaces);
        }

        [Fact]
        public void Sync_RestoresMissingAppRules()
        {
            var ks = Create(new string[0]);   // enabled while Happ was not installed
            ks.EnableClient(Happ);
            Assert.DoesNotContain(fw.Rules, r => r.Name.StartsWith("KS-App-"));

            processes = new List<ProcessEntry> { new ProcessEntry { Name = "Happ.exe", ExePath = TestEnv.HappDir + @"\Happ.exe" } };
            var ks2 = Create();               // now installed and running
            var s = Read(ks2);
            Assert.True(KillSwitch.NeedsClientSync(s));
            ks2.SyncClients(s);

            Assert.Contains(fw.Rules, r => r.Name == "KS-App-happ-xray");
        }

        [Fact]
        public void Disabled_NoSync()
        {
            var s = Read(Create());
            Assert.False(s.IsClientEnabled("happ"));
            Assert.False(KillSwitch.NeedsClientSync(s));
        }
    }
}
