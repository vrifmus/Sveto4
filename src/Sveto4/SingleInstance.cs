using System;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace Sveto4
{
    /// <summary>
    /// One running copy per machine. Any program can create a named mutex, so an existing one counts
    /// as another copy of Sveto4 only if administrators own it: a non-administrator cannot set
    /// that owner, and a mutex planted by one must not keep Sveto4 from starting.
    /// </summary>
    internal static class SingleInstance
    {
        public const string MutexName = @"Global\Sveto4.SingleInstance";

        /// <summary>An existing mutex with this owner was created by another copy (Sveto4 always runs elevated).</summary>
        public static bool IsOtherCopy(string ownerSid) => ownerSid != null && FolderSecurity.IsTrustedSid(ownerSid);

        /// <summary>
        /// False if another copy runs. Otherwise <paramref name="mutex"/> must be kept alive while the app runs
        /// (null if the name is taken by someone else); <paramref name="warning"/> is set when the mutex was planted.
        /// The log is not written here: its folder is not set up yet.
        /// </summary>
        public static bool TryAcquire(out Mutex mutex, out string warning)
        {
            warning = null;
            mutex = null;
            try
            {
                var security = new MutexSecurity();
                var admins = new SecurityIdentifier(FolderSecurity.AdministratorsSid);
                security.SetOwner(admins);
                security.AddAccessRule(new MutexAccessRule(admins, MutexRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(FolderSecurity.SystemSid),
                    MutexRights.FullControl, AccessControlType.Allow));

                mutex = new Mutex(true, MutexName, out var created, security);
                if (created) return true;

                string owner;
                try
                {
                    owner = mutex.GetAccessControl().GetOwner(typeof(SecurityIdentifier))?.Value;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException || ex is InvalidOperationException)
                {
                    owner = null;
                }
                if (IsOtherCopy(owner))
                {
                    mutex.Dispose();
                    mutex = null;
                    return false;
                }
                warning = $"Single-instance mutex is held by a non-administrator ({owner ?? "owner unknown"}), starting anyway";
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                // The existing mutex denies access to administrators: Sveto4 never creates it like that.
                mutex = null;
                warning = "Single-instance mutex is held by a non-administrator (access denied), starting anyway";
                return true;
            }
        }
    }
}
