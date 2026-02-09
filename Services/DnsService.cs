using System.Diagnostics;
using System.Net;
using System.Text;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class DnsService : IDnsService
{
    public async Task<List<TrafficItem>> GetDnsCacheAsync()
    {
        var list = new List<TrafficItem>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ipconfig",
                Arguments = "/displaydns",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.GetEncoding(866)
            };

            using var proc = Process.Start(psi);
            if (proc == null) return list;

            var output = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();

            var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var host = "";

            var filter = new[] { "ea.com", "google", "steam", "aws", "respawn", "akamai", "discord" };

            foreach (var line in lines)
            {
                var row = line.Trim();
                if (string.IsNullOrEmpty(row)) continue;

                if (row.Contains("Record Name") || row.Contains("Имя записи"))
                {
                    host = row.Split(':').Last().Trim();
                }
                else if (row.Contains("A (Host)") || row.Contains("А (хост)"))
                {
                    if (string.IsNullOrEmpty(host)) continue;

                    if (filter.Any(f => host.Contains(f, StringComparison.OrdinalIgnoreCase)))
                        if (!list.Any(x => x.Domain == host))
                            list.Add(new TrafficItem
                            {
                                Domain = host,
                                RemoteIP = "DNS Cache",
                                Protocol = "DNS",
                                Status = "Cached",
                                TrafficType = "SYSTEM"
                            });
                }
            }
        }
        catch
        {
        }

        return list;
    }

    public async Task<string> ResolveHostNameAsync(string ip)
    {
        if (string.IsNullOrEmpty(ip) || ip == "---") return "";

        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            return entry.HostName ?? "";
        }
        catch
        {
            return "";
        }
    }
}
