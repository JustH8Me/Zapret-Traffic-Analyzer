using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using ZapretTraficAnalyz.Interfaces;

namespace ZapretTraficAnalyz.Services;

public class NetworkCheckerService : INetworkCheckerService
{
    public async Task<(bool IsAccessible, string Error)> CheckAccessAsync(string ip, string domain, string protocol)
    {
        try
        {
            if (!string.IsNullOrWhiteSpace(domain) && domain != "---")
            {
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
                };

                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
                await client.GetAsync($"https://{domain}", HttpCompletionOption.ResponseHeadersRead);
                return (true, "HTTPS OK");
            }

            if (protocol != null && protocol.Contains("UDP"))
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 1500);

                if (reply.Status == IPStatus.Success)
                    return (true, $"Ping {reply.RoundtripTime}ms");

                return (false, $"Ping {reply.Status}");
            }

            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(1500);

            await tcp.ConnectAsync(ip, 443).WaitAsync(cts.Token);

            return (true, "TCP Connect OK");
        }
        catch (OperationCanceledException)
        {
            return (false, "Timeout");
        }
        catch (Exception ex)
        {
            return (false, ex.InnerException?.Message ?? ex.Message);
        }
    }
}
