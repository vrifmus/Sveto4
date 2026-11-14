using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Sveto4
{
    /// <summary>One access control entry, reduced to what the admin-only check needs.</summary>
    internal sealed class AceInfo
    {
        public AceInfo(string sid, FileSystemRights rights, bool allow = true, bool inheritOnly = false)
        {
            Sid = sid;
            Rights = rights;
            Allow = allow;
            InheritOnly = inheritOnly;
        }

        public string Sid { get; }
        public FileSystemRights Rights { get; }
        public bool Allow { get; }
        /// <summary>Applies only to children, not to the object itself.</summary>
        public bool InheritOnly { get; }
    }

    /// <summary>
    /// Checks whether only administrators can change a file or folder. Used for folders whose
    /// executables are allowed past the Kill Switch and for the app's own data files.
    /// </summary>
    internal static class FolderSecurity
    {
        public const string SystemSid = "S-1-5-18";
        public const string AdministratorsSid = "S-1-5-32-544";
        public const string TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

        private static readonly HashSet<string> TrustedSids =
            new HashSet<string>(new[] { SystemSid, AdministratorsSid, TrustedInstallerSid }, StringComparer.OrdinalIgnoreCase);

        // GENERIC_ALL and GENERIC_WRITE have no FileSystemRights members.
        private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
        private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;
        private const FileSystemRights Takeover = FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll;

        /// <summary>Rights on the object itself that let someone plant, replace or remove its contents.</summary>
        public const FileSystemRights TargetRights =
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete
            | FileSystemRights.DeleteSubdirectoriesAndFiles | Takeover | GenericWrite;

        /// <summary>Rights on a parent folder that let someone rename the path away and recreate it.</summary>
        public const FileSystemRights AncestorRights =
            FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles | Takeover;

        /// <summary>Drive roots cannot be renamed, so Delete on them does not matter (D:\ grants it to all users).</summary>
        public const FileSystemRights RootRights = FileSystemRights.DeleteSubdirectoriesAndFiles | Takeover;

        // ---------- Pure logic ----------

        /// <summary>SYSTEM, Administrators or TrustedInstaller.</summary>
        public static bool IsTrustedSid(string sid) => sid != null && TrustedSids.Contains(sid);

        /// <summary>
        /// True when the owner is trusted and no other principal is granted any of <paramref name="forbidden"/>.
        /// An untrusted owner can always rewrite the permissions.
        /// </summary>
        public static bool IsAdminOnly(string ownerSid, IEnumerable<AceInfo> aces, FileSystemRights forbidden) =>
            ownerSid != null && TrustedSids.Contains(ownerSid)
            && !aces.Any(a => a.Allow && !a.InheritOnly && !TrustedSids.Contains(a.Sid) && (a.Rights & forbidden) != 0);

        // ---------- System access ----------

        /// <summary>
        /// The folder and every folder above it can be changed by administrators only.
        /// False if the permissions cannot be read.
        /// </summary>
        public static bool IsAdminOnlyFolder(string dir)
        {
            try
            {
                var target = new DirectoryInfo(Path.GetFullPath(dir));
                for (var d = target; d != null; d = d.Parent)
                {
                    var forbidden = d == target ? TargetRights : d.Parent == null ? RootRights : AncestorRights;
                    var security = d.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
                    if (!IsAdminOnly(Owner(security), Aces(security), forbidden)) return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "read permissions of " + dir);
                return false;
            }
        }

        /// <summary>The file or folder itself can be changed by administrators only (parents are not checked).</summary>
        public static bool IsAdminOnlyItem(string path)
        {
            var security = Read(path);
            return IsAdminOnly(Owner(security), Aces(security), TargetRights);
        }

        /// <summary>
        /// Gives the file or folder to Administrators and replaces its permissions with the ones inherited
        /// from its parent. Fixes items moved in from elsewhere: a move keeps the permissions of the old location.
        /// </summary>
        public static void ResetItem(string path)
        {
            // The owner is written first: re-inheriting resolves CREATOR OWNER entries to the current owner.
            var isDir = Directory.Exists(path);
            var owner = isDir ? (FileSystemSecurity)new DirectorySecurity() : new FileSecurity();
            owner.SetOwner(new SecurityIdentifier(AdministratorsSid));
            Write(path, owner);

            var security = Read(path);
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                security.RemoveAccessRuleSpecific(rule);
            security.SetAccessRuleProtection(false, false);
            // SetNamedSecurityInfo drops stale inherited entries and re-inherits from the parent.
            Write(path, security);
        }

        /// <summary>Writes only the sections changed in <paramref name="security"/>.</summary>
        private static void Write(string path, FileSystemSecurity security)
        {
            if (security is DirectorySecurity dir) Directory.SetAccessControl(path, dir);
            else File.SetAccessControl(path, (FileSecurity)security);
        }

        private static FileSystemSecurity Read(string path)
        {
            const AccessControlSections sections = AccessControlSections.Owner | AccessControlSections.Access;
            return Directory.Exists(path)
                ? (FileSystemSecurity)Directory.GetAccessControl(path, sections)
                : File.GetAccessControl(path, sections);
        }

        private static string Owner(FileSystemSecurity security) =>
            (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value;

        private static IEnumerable<AceInfo> Aces(FileSystemSecurity security) =>
            security.GetAccessRules(true, true, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Select(r => new AceInfo(r.IdentityReference.Value, r.FileSystemRights,
                    r.AccessControlType == AccessControlType.Allow,
                    (r.PropagationFlags & PropagationFlags.InheritOnly) != 0));
    }
}
