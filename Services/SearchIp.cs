using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class SearchIp
{
    private TraceEventSession? _session;
    private HashSet<int> _pids = [];
    private readonly ConcurrentDictionary<string, string> _dns = new();

    public event Action<TrafficItem>? TrafficDetected;

    public void Start(IEnumerable<int> pids, string procName)
    {
        _pids = [.. pids];
        _dns.Clear();

        Task.Run(() =>
        {
            try
            {
                using var session = new TraceEventSession("Z_" + Guid.NewGuid());
                _session = session;

                session.EnableKernelProvider(KernelTraceEventParser.Keywords.NetworkTCPIP);
                session.EnableProvider(new Guid("1C95126E-7EEA-49A9-A3FE-13F15C179B51")); 

                // Слушаем TCP и UDP
                session.Source.Kernel.TcpIpConnect += d => ProcessNet(d.ProcessID, d.daddr.ToString(), "TCP", procName);
                session.Source.Kernel.UdpIpSend += d => ProcessNet(d.ProcessID, d.daddr.ToString(), "UDP", procName);

                // Слушаем DNS
                session.Source.Dynamic.All += d =>
                {
                    if (!_pids.Contains(d.ProcessID) || !d.EventName.Contains("Query")) return;

                    var host = d.PayloadByName("QueryName")?.ToString();
                    var res = d.PayloadByName("QueryResults")?.ToString();

                    if (host != null && res != null)
                    {
                        var match = Regex.Match(res, @"\d+\.\d+\.\d+\.\d+");
                        if (match.Success) _dns[match.Value] = host.TrimEnd('.');
                    }
                };

                session.Source.Process();
            }
            catch { }
        });
    }

    private void ProcessNet(int pid, string ip, string proto, string procName)
    {
        if (!_pids.Contains(pid)) return;
        if (ip.StartsWith("127.") || ip.StartsWith("10.") || ip.StartsWith("192.168.")) return;

        _dns.TryGetValue(ip, out var domain);

        TrafficDetected?.Invoke(new TrafficItem
        {
            Time = DateTime.Now.ToString("HH:mm:ss"),
            Process = procName,
            RemoteIP = ip,
            Domain = domain ?? "---",
            Protocol = proto
        });
    }

    public void Stop()
    {
        _session?.Stop();
        _session?.Dispose();
    }
}