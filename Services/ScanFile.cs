using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Linq;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class ScanFile : IFileScannerService
{
    private static readonly HashSet<string> InvalidTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "png", "jpg", "jpeg", "gif", "bmp", "exe", "dll", "lib", "obj", "pdb",
        "wav", "mp3", "ogg", "zip", "rar", "pak", "dat", "bin", "cfg", "ini",
        "xml", "json", "html", "css", "js", "cpp", "h", "cs"
    };


    private static readonly HashSet<string> SkipExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bik", ".bk2", ".mp4", ".avi", ".mkv", ".webm", ".mov",
        ".wav", ".mp3", ".ogg", ".wma", ".aac", ".flac",
        ".png", ".jpg", ".jpeg", ".tga", ".dds", ".gif", ".psd",
        ".zip", ".rar", ".7z", ".pak", ".vpk", ".cas", ".cab"
    };

    private readonly ConcurrentDictionary<string, byte> _alreadyFound = new();
    private const long MaxFileSizeBytes = 50L * 1024 * 1024;
    public event Action<TrafficItem>? ItemFound;
    public event Action<string>? StatusUpdated;

    public async Task RunScanAsync(string rootPath)
    {
        _alreadyFound.Clear();
        await Task.Run(() =>
        {
            try
            {
                StatusUpdated?.Invoke("Глубокий анализ папки...");

                var files = Directory.EnumerateFiles(rootPath, "*.*", SearchOption.AllDirectories)
                    .Where(f => !SkipExtensions.Contains(Path.GetExtension(f)))
                    .ToList();

                var total = files.Count;
                var processed = 0;

                Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                    file =>
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length < MaxFileSizeBytes) ProcessUniversal(file);
                        }
                        catch
                        {
                        }

                        var c = Interlocked.Increment(ref processed);
                        if (c % 50 == 0) StatusUpdated?.Invoke($"Scan: {c}/{total} | Найдено: {_alreadyFound.Count}");
                    });

                StatusUpdated?.Invoke($"Готово. Найдено уникальных записей: {_alreadyFound.Count}");
            }
            catch (Exception ex)
            {
                StatusUpdated?.Invoke("Ошибка: " + ex.Message);
            }
        });
    }

    private void ProcessUniversal(string filePath)
    {
        try
        {
            var bytes = File.ReadAllBytes(filePath);
            var strings = ExtractStrings(bytes);

            foreach (var line in strings)
            {
                var candidate = CleanString(line);

                if (string.IsNullOrWhiteSpace(candidate)) continue;

                if (!IsValidDomainUniversal(candidate)) continue;

                NotifyFound(candidate, filePath);
            }
        }
        catch
        {
        }
    }

    private List<string> ExtractStrings(byte[] data)
    {
        var results = new List<string>();
        var minLen = 5;

        var sbAscii = new StringBuilder();
        var sbUnicode = new StringBuilder();

        for (var i = 0; i < data.Length; i++)
        {
            var b = data[i];
            var c = (char)b;

            if (IsReadable(c))
            {
                sbAscii.Append(c);
            }
            else
            {
                if (sbAscii.Length >= minLen) results.Add(sbAscii.ToString());
                sbAscii.Clear();
            }

            if (i < data.Length - 1)
            {
                var b2 = data[i + 1];
                if (b2 == 0 && IsReadable(c))
                {
                    sbUnicode.Append(c);
                    i++;
                }
                else
                {
                    if (sbUnicode.Length >= minLen) results.Add(sbUnicode.ToString());
                    sbUnicode.Clear();
                }
            }
        }

        if (sbAscii.Length >= minLen) results.Add(sbAscii.ToString());
        if (sbUnicode.Length >= minLen) results.Add(sbUnicode.ToString());

        return results;
    }

    private bool IsReadable(char c)
    {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' ||
               c == '_';
    }

    private string CleanString(string raw)
    {
        var s = raw;
        if (s.Contains("://")) s = s.Substring(s.IndexOf("://") + 3);
        var slash = s.IndexOf('/');
        if (slash > 0) s = s.Substring(0, slash);
        var colon = s.IndexOf(':');
        if (colon > 0) s = s.Substring(0, colon);
        return s.Trim('.');
    }

    private bool IsValidDomainUniversal(string domain)
    {
        if (domain.Length < 5) return false;
        if (!domain.Contains('.')) return false;

        var parts = domain.Split('.');
        if (parts.Length < 2) return false;

        var tld = parts[^1];
        var name = parts[^2];

        if (InvalidTlds.Contains(tld)) return false;

        if (tld.Any(char.IsDigit)) return false;
        if (tld.Length < 2 || tld.Length > 10) return false;

        if (name.Length < 3) return false;

        if (IsGarbageCase(domain)) return false;

        if (parts.All(p => int.TryParse(p, out _))) return false;

        return true;
    }

    private bool IsGarbageCase(string s)
    {
        var switches = 0;
        bool? lastUpper = null;
        foreach (var c in s)
        {
            if (!char.IsLetter(c)) continue;
            var currUpper = char.IsUpper(c);
            if (lastUpper != null && lastUpper != currUpper) switches++;
            lastUpper = currUpper;
        }

        return switches > 3;
    }

    private void NotifyFound(string domain, string filePath)
    {
        var val = domain.ToLowerInvariant();
        if (!_alreadyFound.TryAdd(val, 0)) return;

        var type = "Artifact";
        var color = "White";

        if (val.Contains("api") || val.Contains("auth"))
        {
            type = "API Endpoint";
            color = "#ADD8E6";
        }
        else if (val.Contains("cdn") || val.Contains("update") || val.Contains("download"))
        {
            type = "Update Server";
            color = "#90EE90";
        }
        else if (val.Contains("telemetry") || val.Contains("logs") || val.Contains("metrics"))
        {
            type = "Telemetry";
            color = "Gray";
        }
        else if (val.Contains("discord"))
        {
            type = "Discord";
            color = "#7289DA";
        }
        else if (val.Contains("telegram"))
        {
            type = "Telegram";
            color = "#0088cc";
        }
        else if (filePath.EndsWith(".cfg") || filePath.EndsWith(".ini") || filePath.EndsWith(".json"))
        {
            type = "Config Value";
            color = "#E0FFFF";
        }

        ItemFound?.Invoke(new TrafficItem
        {
            Domain = val,
            RemoteIP = "FILE",
            Protocol = type,
            Status = "Found",
            StatusColor = color,
            ProviderName = Path.GetFileName(filePath),
            Time = DateTime.Now.ToString("HH:mm")
        });
    }
}
