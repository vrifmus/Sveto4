using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace Sveto4
{
    internal sealed class ProfileException : Exception
    {
        public ProfileException(string message) : base(message) { }
    }

    /// <summary>JSON form of a client profile (see docs/profiles/*.json).</summary>
    [DataContract]
    internal sealed class ProfileJson
    {
        [DataMember(Name = "id")] public string Id;
        [DataMember(Name = "name")] public string Name;
        [DataMember(Name = "adapterDescriptions")] public string[] AdapterDescriptions;
        [DataMember(Name = "adapterNamePrefixes")] public string[] AdapterNamePrefixes;
        [DataMember(Name = "mainProcesses")] public string[] MainProcesses;
        [DataMember(Name = "defaultInstallDirs")] public string[] DefaultInstallDirs;
        [DataMember(Name = "excludeExe")] public string[] ExcludeExe;
        [DataMember(Name = "allowExe")] public string[] AllowExe;
    }

    /// <summary>Parses and validates imported client profiles. Pure: no file or system access.</summary>
    internal static class ProfileFile
    {
        public const int MaxSize = 64 * 1024;
        /// <summary>No '-': rule names are KS-App-{id}-{exe}, so "happ" and "happ-x" would share a prefix.</summary>
        private static readonly Regex IdPattern = new Regex("^[a-z0-9]{1,20}$");
        private const int MinPrefixLength = 3;

        /// <param name="existingIds">Ids already in use (built-in and imported).</param>
        public static ClientProfile Parse(string json, IEnumerable<string> existingIds)
        {
            if (string.IsNullOrWhiteSpace(json)) throw new ProfileException("The file is empty.");
            if (json.Length > MaxSize) throw new ProfileException("The file is too large for a profile.");

            ProfileJson data;
            try
            {
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                    data = (ProfileJson)new DataContractJsonSerializer(typeof(ProfileJson)).ReadObject(stream);
            }
            catch (Exception ex) when (ex is SerializationException || ex is InvalidCastException || ex is ArgumentException)
            {
                throw new ProfileException("The file is not a valid profile JSON: " + ex.Message);
            }
            if (data == null) throw new ProfileException("The file is not a valid profile JSON.");

            var profile = new ClientProfile
            {
                Id = (data.Id ?? "").Trim(),
                Name = (data.Name ?? "").Trim(),
                AdapterDescriptions = Clean(data.AdapterDescriptions),
                AdapterNamePrefixes = Clean(data.AdapterNamePrefixes),
                MainProcesses = Clean(data.MainProcesses),
                DefaultInstallDirs = Clean(data.DefaultInstallDirs),
                ExcludeExe = Clean(data.ExcludeExe),
                AllowExe = Clean(data.AllowExe),
            };
            Validate(profile, existingIds);
            return profile;
        }

        private static string[] Clean(string[] values) =>
            (values ?? new string[0]).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v.Trim()).ToArray();

        private static void Validate(ClientProfile p, IEnumerable<string> existingIds)
        {
            if (!IdPattern.IsMatch(p.Id))
                throw new ProfileException("\"id\" must be 1-20 characters: lowercase latin letters and digits.");
            if (existingIds.Any(id => string.Equals(id, p.Id, StringComparison.OrdinalIgnoreCase)))
                throw new ProfileException($"A profile with id \"{p.Id}\" already exists. Remove it first.");
            if (p.Name.Length == 0 || p.Name.Length > 40 || p.Name.Any(char.IsControl))
                throw new ProfileException("\"name\" must be 1-40 characters on one line.");

            if (p.AdapterDescriptions.Length == 0 && p.AdapterNamePrefixes.Length == 0)
                throw new ProfileException("Set \"adapterDescriptions\" or \"adapterNamePrefixes\": how to recognize the client's tunnel adapter.");
            if (p.AdapterNamePrefixes.Any(x => x.Length < MinPrefixLength))
                throw new ProfileException($"Each \"adapterNamePrefixes\" value must be at least {MinPrefixLength} characters.");

            if (p.MainProcesses.Any(x => !IsFileName(x) || !x.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                throw new ProfileException("\"mainProcesses\" must be exe file names without folders, e.g. \"client.exe\".");
            if (p.AllowExe.Concat(p.ExcludeExe).Any(x => !IsFileName(x)))
                throw new ProfileException("\"allowExe\" and \"excludeExe\" must be file names or patterns without folders.");

            foreach (var dir in p.DefaultInstallDirs)
            {
                var expanded = Environment.ExpandEnvironmentVariables(dir);
                if (!Path.IsPathRooted(expanded) || ClientProfiles.IsUnsafeInstallDir(expanded))
                    throw new ProfileException($"\"defaultInstallDirs\": \"{dir}\" is not allowed. Use the client's own folder, not a drive root, Windows, Program Files or a user profile root.");
            }
        }

        private static bool IsFileName(string value) =>
            value.IndexOfAny(new[] { '\\', '/', ':' }) < 0 && value.IndexOfAny(Path.GetInvalidFileNameChars().Where(c => c != '*' && c != '?').ToArray()) < 0;
    }
}
