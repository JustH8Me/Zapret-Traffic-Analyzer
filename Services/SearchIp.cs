using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class SearchIp
{
    private TraceEventSession? _session;
    private readonly ConcurrentDictionary<int, bool> _pids = new();
    private readonly ConcurrentDictionary<string, string> _dnsCache = new();
    private const string SessName = "Zapret_Ultimate_Sniffer";

    public event Action<TrafficItem>? TrafficDetected;

    public void Start(string targetName)
    {
        Stop();
        _pids.Clear(); _dnsCache.Clear();
        string cleanName = targetName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);

        Task.Run(() =>
        {
            try
            {
                using (var old = new TraceEventSession(SessName)) { old.Stop(true); }
                _session = new TraceEventSession(SessName);
                _session.StopOnDispose = true;
                
                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP | 
                    KernelTraceEventParser.Keywords.Process 
                );

                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.EnableProvider("Microsoft-Windows-Schannel");
                
                _session.Source.Kernel.ProcessStart += d => {
                    if (d.ProcessName.Contains(cleanName, StringComparison.OrdinalIgnoreCase) || 
                        d.ProcessName.Contains("steam", StringComparison.OrdinalIgnoreCase) ||
                        d.ProcessName.Contains("ea", StringComparison.OrdinalIgnoreCase))
                    {
                        _pids.TryAdd(d.ProcessID, true);
                    }
                };
                
                foreach (var p in Process.GetProcesses()) {
                    if (p.ProcessName.Contains(cleanName, StringComparison.OrdinalIgnoreCase) || 
                        p.ProcessName.Contains("steam", StringComparison.OrdinalIgnoreCase))
                        _pids.TryAdd(p.Id, true);
                }
                
                _session.Source.Kernel.TcpIpConnect += d => OnNet(d.ProcessID, d.daddr.ToString(), "TCP");
                _session.Source.Kernel.TcpIpSend += d => OnNet(d.ProcessID, d.daddr.ToString(), "TCP");
                _session.Source.Kernel.UdpIpSend += d => OnNet(d.ProcessID, d.daddr.ToString(), "UDP");
                
                _session.Source.Dynamic.All += d => {
                    if (!_pids.ContainsKey(d.ProcessID)) return;
                    
                    if (d.EventName.Contains("Query")) {
                        var host = d.PayloadByName("QueryName")?.ToString();
                        var res = d.PayloadByName("QueryResults")?.ToString();
                        if (host != null && res != null) {
                            var m = Regex.Match(res, @"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
                            if (m.Success) _dnsCache[m.Value] = host.TrimEnd('.');
                        }
                    }

                    if (d.ProviderName == "Microsoft-Windows-Schannel") {
                        var remoteHost = d.PayloadByName("TargetName")?.ToString();
                        if (!string.IsNullOrEmpty(remoteHost)) {
                             _dnsCache["LAST_SNI_" + d.ProcessID] = remoteHost;
                        }
                    }
                };

                _session.Source.Process();
            }
            catch { /* Админ права? */ }
        });
    }

    private void OnNet(int pid, string ip, string proto) {
        if (!_pids.ContainsKey(pid) || ip.StartsWith("127.") || ip.Contains(":")) return;

        _dnsCache.TryGetValue(ip, out var domain);
        
        if (domain == null) _dnsCache.TryGetValue("LAST_SNI_" + pid, out domain);

        TrafficDetected?.Invoke(new TrafficItem {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            RemoteIP = ip,
            Domain = domain ?? "---",
            Protocol = proto
        });
    }

    public void Stop() { _session?.Stop(); _session?.Dispose(); }
}