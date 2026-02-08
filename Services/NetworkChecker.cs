using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ZapretTraficAnalyz.Services;

public static class NetworkChecker
{
    public static async Task<(bool ok, string msg)> CheckAsync(string ip, string domain, string proto)
    {
        try
        {
            //Если есть домен HTTPS (443)
            if (domain != "---")
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                var res = await client.GetAsync($"https://{domain}", HttpCompletionOption.ResponseHeadersRead);
                return (true, "OK");
            }

            //  Если UDP  пинг
            if (proto == "UDP")
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ip, 1500);
                return (reply.Status == IPStatus.Success, "Ping");
            }

            // Если TCP IP соединение
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(1500);
            await tcp.ConnectAsync(ip, 443).WaitAsync(cts.Token);
            return (true, "TCP OK");
        }
        catch
        {
            return (false, "Fail");
        }
    }
}