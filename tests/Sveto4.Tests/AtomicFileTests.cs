using System;
using System.IO;
using Xunit;

namespace Sveto4.Tests
{
    /// <summary>Works in a temporary folder of its own; the app's data folder is not touched.</summary>
    public sealed class AtomicFileTests : IDisposable
    {
        private readonly string dir = Path.Combine(Path.GetTempPath(), "Sveto4.Tests." + Guid.NewGuid().ToString("N"));
        private string FilePath => Path.Combine(dir, "settings.txt");

        public AtomicFileTests() => Directory.CreateDirectory(dir);

        public void Dispose() => Directory.Delete(dir, true);

        [Fact]
        public void CreatesNewFile()
        {
            AtomicFile.WriteAllText(FilePath, "a=1");
            Assert.Equal("a=1", File.ReadAllText(FilePath));
            Assert.Equal(new[] { FilePath }, Directory.GetFiles(dir));
        }

        [Fact]
        public void ReplacesExistingFile_NoTempLeft()
        {
            File.WriteAllText(FilePath, "old contents that are longer");
            AtomicFile.WriteAllText(FilePath, "new");
            Assert.Equal("new", File.ReadAllText(FilePath));
            Assert.Equal(new[] { FilePath }, Directory.GetFiles(dir));
        }

        [Fact]
        public void LeftoverTempFile_IsOverwritten()
        {
            File.WriteAllText(FilePath + ".tmp", "interrupted");
            AtomicFile.WriteAllText(FilePath, "new");
            Assert.Equal("new", File.ReadAllText(FilePath));
            Assert.False(File.Exists(FilePath + ".tmp"));
        }

        [Fact]
        public void WriteAllLines_SameAsFileWriteAllLines()
        {
            var lines = new[] { "a=1", "b=2" };
            AtomicFile.WriteAllLines(FilePath, lines);
            var expected = Path.Combine(dir, "expected.txt");
            File.WriteAllLines(expected, lines);
            Assert.Equal(File.ReadAllBytes(expected), File.ReadAllBytes(FilePath));
        }
    }
}
