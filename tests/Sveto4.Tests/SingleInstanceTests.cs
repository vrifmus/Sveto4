using Xunit;

namespace Sveto4.Tests
{
    public class SingleInstanceTests
    {
        [Theory]
        [InlineData(FolderSecurity.AdministratorsSid, true)]
        [InlineData(FolderSecurity.SystemSid, true)]
        [InlineData("S-1-5-21-1000-1000-1000-1001", false)] // a user account
        [InlineData("S-1-1-0", false)]                       // Everyone
        [InlineData(null, false)]                            // owner could not be read
        public void IsOtherCopy_OnlyForAdministratorOwner(string ownerSid, bool expected) =>
            Assert.Equal(expected, SingleInstance.IsOtherCopy(ownerSid));
    }
}
