using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Sveto4.Tests
{
    /// <summary>In-memory profile store: never touches the disk.</summary>
    internal sealed class FakeProfileStore : IProfileStore
    {
        public readonly Dictionary<string, string> Files = new Dictionary<string, string>();

        public List<ClientProfile> LoadImported()
        {
            var result = new List<ClientProfile>();
            foreach (var json in Files.Values)
                result.Add(ProfileFile.Parse(json, ClientProfiles.BuiltIn.Select(p => p.Id).Concat(result.Select(p => p.Id))));
            return result;
        }

        public void Save(string id, string json) => Files[id] = json;
        public void Delete(string id) => Files.Remove(id);
    }

    public class ProfileImportTests
    {
        private const string NekoDir = @"D:\Apps\NekoBox";

        private static string Neko(string extra = "", string id = "nekobox") => @"{
            ""id"": """ + id + @""",
            ""name"": ""NekoBox"",
            ""adapterDescriptions"": [""sing-tun Tunnel""],
            ""mainProcesses"": [""nekobox.exe"", ""nekobox_core.exe""],
            ""allowExe"": [""nekobox.exe"", ""nekobox_core.exe""]" + extra + @"
        }";

        private static ClientProfile Parse(string json) => ProfileFile.Parse(json, new[] { "happ" });

        private static string Error(string json) => Assert.Throws<ProfileException>(() => Parse(json)).Message;

        // ---------- Parsing and validation ----------

        [Fact]
        public void Parse_ReadsAllFields()
        {
            var p = Parse(Neko(@", ""adapterNamePrefixes"": [""tun_""], ""excludeExe"": [""updater.exe""], ""defaultInstallDirs"": [""D:\\Apps\\NekoBox""]"));

            Assert.Equal("nekobox", p.Id);
            Assert.Equal("NekoBox", p.Name);
            Assert.Equal(new[] { "sing-tun Tunnel" }, p.AdapterDescriptions);
            Assert.Equal(new[] { "tun_" }, p.AdapterNamePrefixes);
            Assert.Equal(new[] { "nekobox.exe", "nekobox_core.exe" }, p.MainProcesses);
            Assert.Equal(new[] { @"D:\Apps\NekoBox" }, p.DefaultInstallDirs);
            Assert.Equal(new[] { "updater.exe" }, p.ExcludeExe);
            Assert.False(p.BuiltIn);
        }

        [Fact]
        public void Parse_DocsSamplesAreValid()
        {
            var dir = System.IO.Path.Combine(AppContext.BaseDirectory, "profiles");
            var files = System.IO.Directory.GetFiles(dir, "*.json");
            Assert.NotEmpty(files);
            foreach (var file in files)
                ProfileFile.Parse(System.IO.File.ReadAllText(file), new string[0]); // happ.json too: no conflict check here
        }

        [Theory]
        [InlineData("Neko-Box")]
        [InlineData("neko-box")]   // '-' would make rule prefixes ambiguous
        [InlineData("")]
        [InlineData("averyveryverylongidentifier")]
        public void Parse_RejectsBadId(string id) => Assert.Contains("\"id\"", Error(Neko(id: id)));

        [Fact]
        public void Parse_RejectsExistingId() => Assert.Contains("already exists", Error(Neko(id: "happ")));

        [Fact]
        public void Parse_RequiresAdapterMatch() =>
            Assert.Contains("adapterDescriptions", Error(@"{ ""id"": ""x"", ""name"": ""X"" }"));

        [Fact]
        public void Parse_RejectsShortPrefix() =>
            Assert.Contains("at least", Error(@"{ ""id"": ""x"", ""name"": ""X"", ""adapterNamePrefixes"": [""t""] }"));

        [Theory]
        [InlineData(@"""mainProcesses"": [""C:\\x\\a.exe""]")]
        [InlineData(@"""allowExe"": [""core\\a.exe""]")]
        public void Parse_RejectsPathsWhereFileNamesExpected(string field) =>
            Assert.Throws<ProfileException>(() => Parse(@"{ ""id"": ""x"", ""name"": ""X"", ""adapterDescriptions"": [""T""], " + field + " }"));

        [Theory]
        [InlineData(@"C:\\")]
        [InlineData(@"%SystemRoot%\\System32")]
        [InlineData(@"%ProgramFiles%")]
        [InlineData(@"%APPDATA%")]
        [InlineData(@"%USERPROFILE%")]
        [InlineData(@"relative\\dir")]
        public void Parse_RejectsUnsafeInstallDirs(string dir) =>
            Assert.Contains("defaultInstallDirs", Error(Neko(@", ""defaultInstallDirs"": [""" + dir + @"""]")));

        [Fact]
        public void Parse_AcceptsClientSubfolderOfAppData() =>
            Assert.Single(Parse(Neko(@", ""defaultInstallDirs"": [""%APPDATA%\\NekoBox""]")).DefaultInstallDirs);

        [Theory]
        [InlineData("not json")]
        [InlineData("[1, 2]")]
        [InlineData("")]
        public void Parse_RejectsGarbage(string json) => Assert.Throws<ProfileException>(() => Parse(json));

        // ---------- allowExe and install folder ----------

        [Theory]
        [InlineData(@"D:\Apps\NekoBox\nekobox_core.exe", false)]
        [InlineData(@"D:\Apps\NekoBox\NEKOBOX.EXE", false)]
        [InlineData(@"D:\Apps\NekoBox\updater.exe", true)]   // not in allowExe
        [InlineData(@"D:\Apps\NekoBox\dropped.exe", true)]
        public void AllowExe_OnlyListedExecutables(string path, bool excluded) =>
            Assert.Equal(excluded, Parse(Neko()).IsExcluded(path));

        [Theory]
        [InlineData(@"C:\", true)]
        [InlineData(@"C:\Windows\System32", true)]
        [InlineData(@"C:\Program Files", true)]
        [InlineData(@"C:\Program Files\FlyFrogLLC\Happ", false)]
        [InlineData(@"D:\Apps\NekoBox", false)]
        public void UnsafeInstallDir(string dir, bool unsafeDir)
        {
            var expanded = dir.Replace(@"C:\Windows", Environment.GetFolderPath(Environment.SpecialFolder.Windows))
                              .Replace(@"C:\Program Files", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            Assert.Equal(unsafeDir, ClientProfiles.IsUnsafeInstallDir(expanded));
        }

        [Fact]
        public void ResolveInstallDir_RejectsClientRunningFromSystemFolder()
        {
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var env = TestEnv.Create(() => new[] { new ProcessEntry { Name = "nekobox.exe", ExePath = system + @"\nekobox.exe" } });
            Assert.Null(ClientProfiles.ResolveInstallDir(Parse(Neko()), env));
        }

        // ---------- Import, use and removal ----------

        private readonly FakeFirewall fw = new FakeFirewall();
        private readonly FakeStore store = new FakeStore();
        private readonly FakeProfileStore profiles = new FakeProfileStore();
        private readonly List<AdapterInfo> adapters = new List<AdapterInfo>
        {
            TestEnv.Adapter("Wi-Fi"),
            TestEnv.Adapter("tun_jvvrwugzd", "sing-tun Tunnel"),
        };

        private KillSwitch Create() => new KillSwitch(fw,
            TestEnv.Create(() => new[] { new ProcessEntry { Name = "nekobox.exe", ExePath = NekoDir + @"\nekobox.exe" } },
                           new[] { NekoDir + @"\nekobox.exe", NekoDir + @"\nekobox_core.exe", NekoDir + @"\updater.exe", NekoDir + @"\uninstall.exe" },
                           adapters),
            store, null, profiles);

        private KsState Read(KillSwitch ks)
        {
            var s = new KsState();
            ks.ReadProfiles(s);
            ks.ReadRules(s);
            ks.ReadAdapters(s);
            return s;
        }

        [Fact]
        public void Import_ProfileAppearsAfterBuiltIn()
        {
            var ks = Create();
            ks.ImportProfile(Neko());

            Assert.Equal(new[] { "happ", "nekobox" }, Read(ks).Clients.Select(c => c.Profile.Id).ToArray());
            Assert.True(profiles.Files.ContainsKey("nekobox"));
        }

        [Fact]
        public void Import_SameIdTwice_Rejected()
        {
            var ks = Create();
            ks.ImportProfile(Neko());
            Assert.Throws<ProfileException>(() => ks.ImportProfile(Neko()));
        }

        [Fact]
        public void Enable_AllowsOnlyListedExeAndRandomlyNamedTunAdapter()
        {
            var ks = Create();
            var neko = ks.ImportProfile(Neko());

            ks.EnableClient(neko);

            Assert.Equal(new[] { "KS-Allow-tun_jvvrwugzd", "KS-App-nekobox-nekobox", "KS-App-nekobox-nekobox_core" },
                         fw.Rules.Select(r => r.Name).OrderBy(n => n).ToArray());

            // Next connection: new random adapter name.
            adapters.RemoveAll(a => a.Name == "tun_jvvrwugzd");
            adapters.Add(TestEnv.Adapter("tun_abcdefgh", "sing-tun Tunnel"));
            var s = Read(ks);
            ks.SyncClients(s);
            Assert.Equal(new[] { "tun_abcdefgh" }, Read(ks).Interfaces.ToArray());
        }

        [Fact]
        public void Remove_DeletesRulesAndProfile()
        {
            var ks = Create();
            var neko = ks.ImportProfile(Neko());
            ks.EnableClient(neko);
            ks.SelectInterface("Wi-Fi");

            ks.RemoveProfile(neko, Read(ks));

            Assert.Equal(new[] { "KS-Allow-Wi-Fi" }, fw.Rules.Select(r => r.Name).ToArray());
            Assert.Empty(profiles.Files);
            Assert.DoesNotContain(Read(ks).Clients, c => c.Profile.Id == "nekobox");
        }

        [Fact]
        public void Remove_Prediction_MatchesResult()
        {
            var ks = Create();
            var neko = ks.ImportProfile(Neko());
            ks.EnableClient(neko);
            var before = Read(ks);

            var predicted = KillSwitch.PredictRemoveProfile(before, neko);
            ks.RemoveProfile(neko, before);
            var actual = Read(ks);

            Assert.Equal(actual.Clients.Select(c => c.Profile.Id), predicted.Clients.Select(c => c.Profile.Id));
            Assert.Equal(actual.Interfaces.OrderBy(i => i), predicted.Interfaces.OrderBy(i => i));
        }

        [Fact]
        public void BuiltIn_CannotBeRemoved() =>
            Assert.Throws<InvalidOperationException>(() => Create().RemoveProfile(ClientProfiles.Happ, new KsState()));

        [Fact]
        public void HappRules_NotTouchedByOtherProfile()
        {
            var ks = Create();
            fw.Rules.Add(new RuleSpec { Name = "KS-App-happ-xray" });
            var neko = ks.ImportProfile(Neko(id: "happx"));
            ks.EnableClient(neko);

            ks.DisableClient(neko, Read(ks));

            Assert.Contains(fw.Rules, r => r.Name == "KS-App-happ-xray");
        }
    }
}
