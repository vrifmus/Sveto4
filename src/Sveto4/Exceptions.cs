using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace Sveto4
{
    /// <summary>Invalid exception input; the message is shown to the user.</summary>
    internal sealed class ExceptionValidationError : Exception
    {
        public ExceptionValidationError(string message) : base(message) { }
    }

    internal enum ExceptionProtocol
    {
        Any,
        Tcp,
        Udp
    }

    /// <summary>
    /// User-defined Allow rule past the Kill Switch: remote addresses (required), optionally limited to
    /// one program and to a protocol/ports. E.g. SSH to the VPN server itself, which is reached outside the tunnel.
    /// </summary>
    internal sealed class ExceptionEntry
    {
        public string Name;
        /// <summary>Normalized firewall addresses, comma-separated (see <see cref="Exceptions.NormalizeAddresses"/>).</summary>
        public string Addresses;
        /// <summary>Full exe path, or null for any program.</summary>
        public string Program;
        public ExceptionProtocol Protocol = ExceptionProtocol.Any;
        /// <summary>Normalized remote ports, or null for any port (only with TCP/UDP).</summary>
        public string Ports;
    }

    /// <summary>An exception and whether its firewall rule is enabled.</summary>
    internal sealed class ExceptionStatus
    {
        public ExceptionStatus(ExceptionEntry entry, bool enabled)
        {
            Entry = entry;
            Enabled = enabled;
        }

        public ExceptionEntry Entry { get; }
        public bool Enabled { get; }
    }

    [DataContract]
    internal sealed class ExceptionJson
    {
        [DataMember(Name = "name", Order = 1)] public string Name;
        [DataMember(Name = "addresses", Order = 2)] public string Addresses;
        [DataMember(Name = "program", Order = 3, EmitDefaultValue = false)] public string Program;
        [DataMember(Name = "protocol", Order = 4)] public string Protocol;
        [DataMember(Name = "ports", Order = 5, EmitDefaultValue = false)] public string Ports;
    }

    [DataContract]
    internal sealed class ExceptionsFileJson
    {
        [DataMember(Name = "exceptions")] public ExceptionJson[] Exceptions;
    }

    /// <summary>Validation, normalization and the JSON file format of exceptions. Pure: no file or system access.</summary>
    internal static class Exceptions
    {
        public const int MaxNameLength = 40;
        public const int MaxAddresses = 20;
        public const int MaxPorts = 10;
        /// <summary>Broader subnets are refused: an exception must not turn the Kill Switch off.</summary>
        public const int MinIpv4Prefix = 8;
        public const int MinIpv6Prefix = 16;

        private static readonly Regex Ipv4Pattern = new Regex(@"^\d{1,3}(\.\d{1,3}){3}$");
        private static readonly Regex PortPattern = new Regex(@"^\d{1,5}$");

        /// <summary>Validates user input and returns a normalized entry.</summary>
        /// <param name="existingNames">Names already in use.</param>
        public static ExceptionEntry Create(string name, string addresses, string program, ExceptionProtocol protocol,
                                            string ports, IEnumerable<string> existingNames)
        {
            var entry = new ExceptionEntry
            {
                Name = ValidateName(name),
                Addresses = NormalizeAddresses(addresses),
                Program = NormalizeProgram(program),
                Protocol = protocol,
                Ports = NormalizePorts(ports, protocol),
            };
            if (existingNames.Any(n => string.Equals(n, entry.Name, StringComparison.OrdinalIgnoreCase)))
                throw new ExceptionValidationError($"An exception named \"{entry.Name}\" already exists.");
            return entry;
        }

        public static string ValidateName(string name)
        {
            name = (name ?? "").Trim();
            if (name.Length == 0 || name.Length > MaxNameLength || name.Any(char.IsControl))
                throw new ExceptionValidationError($"Name must be 1-{MaxNameLength} characters on one line.");
            return name;
        }

        /// <summary>
        /// IP addresses and subnets separated by commas or spaces. IPv4 subnets become "address/mask"
        /// (the form used for the LAN rules), IPv6 subnets stay in CIDR form; host bits are cleared.
        /// </summary>
        public static string NormalizeAddresses(string input)
        {
            var parts = (input ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) throw new ExceptionValidationError("Enter an IP address or subnet.");
            if (parts.Length > MaxAddresses) throw new ExceptionValidationError($"At most {MaxAddresses} addresses.");

            var result = new List<string>();
            foreach (var part in parts)
            {
                var normalized = NormalizeAddress(part);
                if (!result.Contains(normalized, StringComparer.OrdinalIgnoreCase)) result.Add(normalized);
            }
            return string.Join(",", result);
        }

        private static string NormalizeAddress(string text)
        {
            var slash = text.IndexOf('/');
            var addressText = slash < 0 ? text : text.Substring(0, slash);
            var prefixText = slash < 0 ? null : text.Substring(slash + 1);

            IPAddress address;
            var isV4 = Ipv4Pattern.IsMatch(addressText);
            var isV6 = !isV4 && addressText.Contains(':') && addressText.IndexOf('%') < 0;
            if ((!isV4 && !isV6) || !IPAddress.TryParse(addressText, out address)
                || address.AddressFamily != (isV4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6))
                throw new ExceptionValidationError($"\"{text}\" is not an IP address or subnet. Host names are not supported.");

            var bits = isV4 ? 32 : 128;
            var prefix = bits;
            if (prefixText != null && isV4 && Ipv4Pattern.IsMatch(prefixText))
                prefix = MaskToPrefix(prefixText); // "address/mask", the stored form
            else if (prefixText != null && (!int.TryParse(prefixText, out prefix) || prefix < 0 || prefix > bits))
                throw new ExceptionValidationError($"\"{text}\": the subnet prefix must be 0-{bits}.");
            if (prefix < 0) throw new ExceptionValidationError($"\"{text}\": the subnet mask is not valid.");
            var min = isV4 ? MinIpv4Prefix : MinIpv6Prefix;
            if (prefix < min)
                throw new ExceptionValidationError($"\"{text}\" is too broad: the prefix must be at least /{min}.");

            var bytes = address.GetAddressBytes();
            if (bytes.All(b => b == 0)) throw new ExceptionValidationError($"\"{text}\" is not a usable address.");
            if (prefix == bits) return address.ToString();

            for (var i = 0; i < bytes.Length; i++)
            {
                var keep = Math.Max(0, Math.Min(8, prefix - i * 8));
                bytes[i] &= (byte)(0xFF << (8 - keep));
            }
            var network = new IPAddress(bytes).ToString();
            if (!isV6) return network + "/" + Ipv4Mask(prefix);
            return network + "/" + prefix;
        }

        /// <summary>Prefix length of a contiguous IPv4 mask, or -1.</summary>
        private static int MaskToPrefix(string mask)
        {
            if (!IPAddress.TryParse(mask, out var address)) return -1;
            var bytes = address.GetAddressBytes();
            var value = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
            var prefix = 0;
            while (prefix < 32 && (value & (0x80000000u >> prefix)) != 0) prefix++;
            return value == (prefix == 0 ? 0u : uint.MaxValue << (32 - prefix)) ? prefix : -1;
        }

        private static string Ipv4Mask(int prefix)
        {
            var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
            return $"{mask >> 24}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}";
        }

        /// <summary>Empty means any program; otherwise a full path to an exe (environment variables allowed).</summary>
        public static string NormalizeProgram(string program)
        {
            program = (program ?? "").Trim().Trim('"').Trim();
            if (program.Length == 0) return null;
            var expanded = Environment.ExpandEnvironmentVariables(program);
            if (expanded.IndexOfAny(Path.GetInvalidPathChars().Concat(new[] { '*', '?' }).ToArray()) >= 0
                || !Path.IsPathRooted(expanded) || expanded.StartsWith(@"\\")
                || !expanded.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                throw new ExceptionValidationError("Program must be a full path to an .exe file, or empty for any program.");
            return program;
        }

        /// <summary>Ports and ranges separated by commas, e.g. "22" or "80,8000-8100". Empty means any port.</summary>
        public static string NormalizePorts(string ports, ExceptionProtocol protocol)
        {
            var parts = (ports ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return null;
            if (protocol == ExceptionProtocol.Any)
                throw new ExceptionValidationError("Ports require TCP or UDP.");
            if (parts.Length > MaxPorts) throw new ExceptionValidationError($"At most {MaxPorts} ports or ranges.");

            var result = new List<string>();
            foreach (var part in parts)
            {
                var range = part.Split('-');
                if (range.Length > 2 || range.Any(p => !IsPort(p)))
                    throw new ExceptionValidationError($"\"{part}\" is not a port (1-65535) or a range like 8000-8100.");
                var from = int.Parse(range[0]);
                var to = int.Parse(range[range.Length - 1]);
                if (from > to) throw new ExceptionValidationError($"\"{part}\": the range must go from low to high.");
                var normalized = from == to ? from.ToString() : $"{from}-{to}";
                if (!result.Contains(normalized)) result.Add(normalized);
            }
            return string.Join(",", result);
        }

        private static bool IsPort(string text) =>
            PortPattern.IsMatch(text) && int.TryParse(text, out var port) && port >= 1 && port <= 65535;

        /// <summary>IANA protocol number for the firewall: 256 = any.</summary>
        public static int ProtocolNumber(ExceptionProtocol protocol) =>
            protocol == ExceptionProtocol.Tcp ? 6 : protocol == ExceptionProtocol.Udp ? 17 : 256;

        /// <summary>Short description for the menu, e.g. "203.0.113.5 TCP 22".</summary>
        public static string Describe(ExceptionEntry e)
        {
            var text = e.Addresses.Replace(",", ", ");
            if (e.Protocol != ExceptionProtocol.Any) text += " " + e.Protocol.ToString().ToUpperInvariant();
            if (e.Ports != null) text += " " + e.Ports;
            return text;
        }

        // ---------- File format ----------

        public const int MaxFileSize = 256 * 1024;

        /// <summary>Valid entries of the file; invalid ones and duplicates are reported via <paramref name="skipped"/>.</summary>
        public static List<ExceptionEntry> Parse(string json, Action<string> skipped = null)
        {
            var result = new List<ExceptionEntry>();
            if (string.IsNullOrWhiteSpace(json)) return result;
            if (json.Length > MaxFileSize) throw new ExceptionValidationError("The exceptions file is too large.");

            ExceptionsFileJson data;
            try
            {
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                    data = (ExceptionsFileJson)new DataContractJsonSerializer(typeof(ExceptionsFileJson)).ReadObject(stream);
            }
            catch (Exception ex) when (ex is SerializationException || ex is InvalidCastException || ex is ArgumentException)
            {
                throw new ExceptionValidationError("The exceptions file is not valid JSON: " + ex.Message);
            }

            foreach (var item in data?.Exceptions ?? new ExceptionJson[0])
            {
                if (item == null) continue;
                try
                {
                    if (!TryParseProtocol(item.Protocol, out var protocol))
                        throw new ExceptionValidationError($"unknown protocol \"{item.Protocol}\"");
                    result.Add(Create(item.Name, item.Addresses, item.Program, protocol, item.Ports, result.Select(r => r.Name)));
                }
                catch (ExceptionValidationError ex)
                {
                    skipped?.Invoke($"{item.Name}: {ex.Message}");
                }
            }
            return result;
        }

        public static string Serialize(IEnumerable<ExceptionEntry> entries)
        {
            var data = new ExceptionsFileJson
            {
                Exceptions = entries.Select(e => new ExceptionJson
                {
                    Name = e.Name,
                    Addresses = e.Addresses,
                    Program = e.Program,
                    Protocol = e.Protocol.ToString().ToLowerInvariant(),
                    Ports = e.Ports,
                }).ToArray(),
            };
            using (var stream = new MemoryStream())
            {
                using (var writer = JsonReaderWriterFactory.CreateJsonWriter(stream, Encoding.UTF8, false, true, "  "))
                    new DataContractJsonSerializer(typeof(ExceptionsFileJson)).WriteObject(writer, data);
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        private static bool TryParseProtocol(string text, out ExceptionProtocol protocol)
        {
            protocol = ExceptionProtocol.Any;
            if (string.IsNullOrWhiteSpace(text)) return true;
            return Enum.TryParse(text.Trim(), true, out protocol) && Enum.IsDefined(typeof(ExceptionProtocol), protocol);
        }
    }

    /// <summary>Stored exception definitions. Replaced by a fake in tests.</summary>
    internal interface IExceptionStore
    {
        List<ExceptionEntry> Load();
        void Save(List<ExceptionEntry> entries);
    }

    /// <summary>%ProgramData%\Sveto4\exceptions.json (administrators only, see <see cref="AppDataDir"/>).</summary>
    internal sealed class FileExceptionStore : IExceptionStore
    {
        private static string FilePath => Path.Combine(AppDataDir.Path, "exceptions.json");

        public List<ExceptionEntry> Load()
        {
            if (!File.Exists(FilePath)) return new List<ExceptionEntry>();
            AppDataDir.Trust(FilePath);
            return Exceptions.Parse(File.ReadAllText(FilePath), message => Log.Info("Exception skipped: " + message));
        }

        public void Save(List<ExceptionEntry> entries)
        {
            AppDataDir.Trust(FilePath);
            File.WriteAllText(FilePath, Exceptions.Serialize(entries));
        }
    }
}
