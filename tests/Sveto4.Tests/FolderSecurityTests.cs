using System;
using System.Security.AccessControl;
using Xunit;

namespace Sveto4.Tests
{
    public class FolderSecurityTests
    {
        private const string Users = "S-1-5-32-545";
        private const string AuthenticatedUsers = "S-1-5-11";
        private const string SomeUser = "S-1-5-21-1-2-3-1001";
        private const string CreatorOwner = "S-1-3-0";
        private static readonly string Admins = FolderSecurity.AdministratorsSid;

        // ---------- ACL evaluation ----------

        [Fact]
        public void ProgramFilesLikeFolder_IsAdminOnly() =>
            Assert.True(FolderSecurity.IsAdminOnly(Admins, new[]
            {
                new AceInfo(FolderSecurity.TrustedInstallerSid, FileSystemRights.FullControl),
                new AceInfo(FolderSecurity.SystemSid, FileSystemRights.FullControl),
                new AceInfo(Admins, FileSystemRights.FullControl),
                new AceInfo(Users, FileSystemRights.ReadAndExecute),
                new AceInfo(CreatorOwner, FileSystemRights.FullControl, inheritOnly: true),
            }, FolderSecurity.TargetRights));

        [Theory]
        [InlineData(FileSystemRights.Modify)]
        [InlineData(FileSystemRights.CreateFiles)]
        [InlineData(FileSystemRights.ChangePermissions)]
        [InlineData(FileSystemRights.FullControl)]
        public void UserWithWriteRights_IsNotAdminOnly(FileSystemRights rights) =>
            Assert.False(FolderSecurity.IsAdminOnly(Admins, new[] { new AceInfo(Users, rights) }, FolderSecurity.TargetRights));

        [Fact]
        public void GenericWrite_IsNotAdminOnly() =>
            Assert.False(FolderSecurity.IsAdminOnly(Admins, new[] { new AceInfo(Users, (FileSystemRights)0x40000000) },
                FolderSecurity.TargetRights));

        [Fact]
        public void UntrustedOwner_IsNotAdminOnly() =>
            Assert.False(FolderSecurity.IsAdminOnly(SomeUser, new[] { new AceInfo(Admins, FileSystemRights.FullControl) },
                FolderSecurity.TargetRights));

        [Fact]
        public void UnknownOwner_IsNotAdminOnly() =>
            Assert.False(FolderSecurity.IsAdminOnly(null, new AceInfo[0], FolderSecurity.TargetRights));

        [Fact]
        public void DenyAndInheritOnlyEntries_AreIgnored() =>
            Assert.True(FolderSecurity.IsAdminOnly(Admins, new[]
            {
                new AceInfo(Users, FileSystemRights.FullControl, allow: false),
                new AceInfo(AuthenticatedUsers, FileSystemRights.Modify, inheritOnly: true),
            }, FolderSecurity.TargetRights));

        [Fact]
        public void SystemDriveRoot_CreateFoldersIsAllowedForAncestors()
        {
            // C:\ lets authenticated users create folders, which does not let them replace an existing one.
            var aces = new[] { new AceInfo(AuthenticatedUsers, FileSystemRights.AppendData) };
            Assert.True(FolderSecurity.IsAdminOnly(FolderSecurity.TrustedInstallerSid, aces, FolderSecurity.RootRights));
            Assert.False(FolderSecurity.IsAdminOnly(FolderSecurity.TrustedInstallerSid, aces, FolderSecurity.TargetRights));
        }

        [Fact]
        public void DataDriveRoot_DeleteIsIgnoredOnlyForRoot()
        {
            // D:\ grants Modify (includes Delete) to authenticated users; a root cannot be renamed.
            var aces = new[] { new AceInfo(AuthenticatedUsers, FileSystemRights.Modify) };
            Assert.True(FolderSecurity.IsAdminOnly(Admins, aces, FolderSecurity.RootRights));
            Assert.False(FolderSecurity.IsAdminOnly(Admins, aces, FolderSecurity.AncestorRights));
        }

        // ---------- Install folder ----------

        private static readonly ClientProfile Happ = ClientProfiles.Happ;
        private static readonly string HappDefault = Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\FlyFrogLLC\Happ");
        private const string FakeDir = @"D:\Temp\x";

        private static ProcessEntry Process(string path) =>
            new ProcessEntry { Name = System.IO.Path.GetFileName(path), ExePath = path };

        [Fact]
        public void DefaultFolder_PreferredOverRunningProcess()
        {
            var env = TestEnv.Create(() => new[] { Process(FakeDir + @"\Happ.exe") }, files: new[] { HappDefault + @"\Happ.exe" });
            Assert.Equal(HappDefault, ClientProfiles.ResolveInstallDir(Happ, env));
        }

        [Fact]
        public void RunningProcess_InUserWritableFolder_IsRejected()
        {
            var env = TestEnv.Create(() => new[] { Process(FakeDir + @"\Happ.exe") }, userWritableDirs: new[] { FakeDir });
            Assert.Null(ClientProfiles.ResolveInstallDir(Happ, env));
        }

        [Fact]
        public void RunningProcess_InAdminOnlyFolder_IsAccepted()
        {
            var env = TestEnv.Create(() => new[] { Process(@"D:\Apps\Happ\Happ.exe") });
            Assert.Equal(@"D:\Apps\Happ", ClientProfiles.ResolveInstallDir(Happ, env));
        }

        [Fact]
        public void UserWritableDefaultFolder_NeedsAllowExe()
        {
            var noAllow = new ClientProfile { Id = "x", Name = "X", DefaultInstallDirs = new[] { FakeDir } };
            var withAllow = new ClientProfile { Id = "y", Name = "Y", DefaultInstallDirs = new[] { FakeDir }, AllowExe = new[] { "y.exe" } };
            var env = TestEnv.Create(files: new[] { FakeDir + @"\y.exe" }, userWritableDirs: new[] { FakeDir });

            Assert.Null(ClientProfiles.ResolveInstallDir(noAllow, env));
            Assert.Equal(FakeDir, ClientProfiles.ResolveInstallDir(withAllow, env));
        }

        [Fact]
        public void UserWritableProcessFolder_RejectedEvenWithAllowExe() =>
            Assert.NotNull(ClientProfiles.RejectInstallDir(
                new ClientProfile { Id = "y", Name = "Y", AllowExe = new[] { "y.exe" } }, FakeDir, true, _ => false));
    }
}
