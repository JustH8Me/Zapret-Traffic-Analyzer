using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class SearchIp : ISnifferService
{
    private const string SessName = "Zapret_Ultimate_Sniffer";

    private readonly ConcurrentDictionary<string, string> _dnsCache = new();

    private readonly ConcurrentDictionary<int, string> _lastSniCache = new();

    private readonly ConcurrentDictionary<int, bool> _pids = new();

    private readonly ConcurrentDictionary<string, DateTime> _rateLimiter = new();
    private TraceEventSession? _session;

    public event Action<TrafficItem>? TrafficDetected;

    public void Start(string targetName)
    {
        Stop();
        _pids.Clear();
        _dnsCache.Clear();
        _rateLimiter.Clear();
        _lastSniCache.Clear();
        var cleanName = targetName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);

        Task.Run(() => RunSession(cleanName));
    }

    private void RunSession(string cleanName)
    {
        try
        {
            using (var old = new TraceEventSession(SessName))
            {
                old.Stop(true);
            }

            _session = new TraceEventSession(SessName) { StopOnDispose = true };

            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.Process
            );

            _session.EnableProvider("Microsoft-Windows-DNS-Client");
            _session.EnableProvider("Microsoft-Windows-Schannel", TraceEventLevel.Informational, 0x4);

            _session.Source.Kernel.ProcessStart += d =>
            {
                if (d.ProcessName.Contains(cleanName, StringComparison.OrdinalIgnoreCase))
                    _pids.TryAdd(d.ProcessID, true);
            };

            foreach (var p in Process.GetProcesses())
                if (p.ProcessName.Contains(cleanName, StringComparison.OrdinalIgnoreCase))
                    _pids.TryAdd(p.Id, true);

            _session.Source.Kernel.TcpIpConnect += d => OnNet(d.ProcessID, d.daddr.ToString(), "TCP");
            _session.Source.Kernel.TcpIpSend += d => OnNet(d.ProcessID, d.daddr.ToString(), "TCP");
            _session.Source.Kernel.UdpIpSend += d => OnNet(d.ProcessID, d.daddr.ToString(), "UDP");
            _session.Source.Kernel.TcpIpRecv += d => OnNet(d.ProcessID, d.saddr.ToString(), "TCP");
            _session.Source.Kernel.UdpIpRecv += d => OnNet(d.ProcessID, d.saddr.ToString(), "UDP");

            _session.Source.Dynamic.All += d =>
            {
                if (!_pids.ContainsKey(d.ProcessID)) return;

                if (d.ProviderName == "Microsoft-Windows-DNS-Client" && d.EventName.Contains("Query"))
                {
                    var host = d.PayloadByName("QueryName")?.ToString();
                    var res = d.PayloadByName("QueryResults")?.ToString();

                    if (host != null && res != null)
                    {
                        var m = Regex.Match(res, @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
                        if (m.Success) _dnsCache[m.Value] = host.TrimEnd('.');
                    }
                }

                if (d.ProviderName == "Microsoft-Windows-Schannel")
                {
                    var target = d.PayloadByName("TargetName")?.ToString();
                    if (string.IsNullOrEmpty(target)) target = d.PayloadByName("ServerName")?.ToString();
                    if (!string.IsNullOrEmpty(target)) _lastSniCache[d.ProcessID] = target.TrimEnd('.');
                }
            };

            _session.Source.Process();
        }
        catch (Exception ex)
        {
            Debug.WriteLine("ETW Error: " + ex.Message);
        }
    }

    public void Stop()
    {
        _session?.Stop();
        _session?.Dispose();
    }

    private void OnNet(int pid, string ip, string proto)
    {
        if (!_pids.ContainsKey(pid) || ip.StartsWith("127.") || ip.Contains(":")) return;

        var key = $"{ip}:{proto}";
        if (_rateLimiter.TryGetValue(key, out var lastTime))
            if ((DateTime.Now - lastTime).TotalMilliseconds < 50)
                return;
        _rateLimiter[key] = DateTime.Now;

        string? domain = null;
        if (!_dnsCache.TryGetValue(ip, out domain)) _lastSniCache.TryGetValue(pid, out domain);

        TrafficDetected?.Invoke(new TrafficItem
        {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            RemoteIP = ip,
            Domain = domain ?? "---",
            Protocol = proto
        });
    }
}
