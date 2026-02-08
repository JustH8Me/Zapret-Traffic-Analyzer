using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ZapretTraficAnalyz.Services;

public static class NetworkChecker
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };

    public static async Task<(bool ok, string msg)> CheckAsync(string ip, string host, string proto)
    {
        try
        {
            // по HTTPS
            if (host != "---")
            {
                var res = await _http.GetAsync($"https://{host}", HttpCompletionOption.ResponseHeadersRead);
                return (true, $"HTTP {(int)res.StatusCode}");
            }

            // Если UDP 
            if (proto == "UDP")
            {
                using var p = new Ping();
                var reply = await p.SendPingAsync(ip, 1500);
                return reply.Status == IPStatus.Success ? (true, $"{reply.RoundtripTime}ms") : (false, "Тайм-аут");
            }

            // Для TCP 443 порту
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(2000);
            await tcp.ConnectAsync(ip, 443).WaitAsync(cts.Token);
            
            return (true, "TCP OK");
        }
        catch
        {
            return (false, "Блок/Отказ");
        }
    }
}