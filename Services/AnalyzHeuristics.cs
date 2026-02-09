using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public static class AnalyzHeuristics
{
    private static readonly string[] VoiceKeywords = { "vivox", "discord", "voice", "rtc", "teamspeak", "sip" };

    private static readonly string[] CdnKeywords =
        { "cdn", "akamai", "cloudfront", "fastly", "limelight", "hwcdn", "assets", "download", "patch" };

    private static readonly string[] ApiKeywords =
        { "api", "auth", "login", "account", "telemetry", "metrics", "gate", "shop", "store" };

    private static readonly string[] AntiCheatKeywords =
        { "easyanticheat", "battleye", "vanguard", "vac", "punkbuster" };

    private static bool IsCommonGamePort(int port)
    {
        return (port >= 27000 && port <= 27100) ||
               (port >= 30000 && port <= 32000) ||
               (port >= 37000 && port <= 38000) ||
               port == 3074;
    }

    public static string Analyze(TrafficItem item)
    {
        var protocol = item.Protocol?.ToUpper() ?? "UNKNOWN";
        var domain = item.Domain?.ToLower() ?? "";
        var host = item.ProviderName?.ToLower() ?? "";


        var port = 0;
        if (!string.IsNullOrEmpty(item.RemoteIP) && item.RemoteIP.Contains(':'))
        {
            var parts = item.RemoteIP.Split(':');
            if (parts.Length > 1) int.TryParse(parts.Last(), out port);
        }


        if (VoiceKeywords.Any(k => domain.Contains(k) || host.Contains(k))) return "VOICE CHAT";

        if (protocol == "UDP" && (port == 5060 || port == 5062 || (port >= 12000 && port <= 17000)))
            return "VOICE CHAT";


        if (protocol == "TCP" && CdnKeywords.Any(k => domain.Contains(k) || host.Contains(k))) return "DOWNLOAD/UPDATE";

        if (AntiCheatKeywords.Any(k => domain.Contains(k) || host.Contains(k))) return "ANTI-CHEAT";

        if (protocol == "TCP" && (port == 443 || port == 80))
        {
            if (ApiKeywords.Any(k => domain.Contains(k))) return "API/AUTH";

            if (item.PacketCount > 500) return "HTTPS STREAM";

            return "WEB/API";
        }

        if (protocol == "UDP")
        {
            if (domain.Contains("match") || domain.Contains("server") || domain.Contains("game")) return "GAMEPLAY";

            if (IsCommonGamePort(port)) return "GAMEPLAY";

            if (item.PacketCount > 100 && port != 53 && port != 123)
            {
                if (host.Contains("amazon") || host.Contains("google") || host.Contains("oracle") ||
                    host.Contains("m247") || host.Contains("i3d")) return "GAMEPLAY (CLOUD)";
                return "GAMEPLAY";
            }
        }

        if (protocol == "TCP")
            if (item.PacketCount > 50 && port != 443 && port != 80)
                return "LOBBY/CHAT";

        if (item.PacketCount > 1000) return "HIGH TRAFFIC";

        return "IDLE/UNKNOWN";
    }
}
