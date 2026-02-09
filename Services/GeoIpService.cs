using System.Net.Http;
using System.Net.Http.Json;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class GeoIpService : IGeoIpService
{
    private readonly HttpClient _httpClient = new() { Timeout = TimeSpan.FromSeconds(3) };

    public async Task<TrafficItem> EnrichWithGeoDataAsync(TrafficItem item)
    {
        if (item.RemoteIP.StartsWith("192.") || item.RemoteIP.StartsWith("10.")) return item;

        try
        {
            var url = $"http://ip-api.com/json/{item.RemoteIP}?fields=status,countryCode,isp,org";
            var response = await _httpClient.GetFromJsonAsync<GeoApiResponse>(url);

            if (response?.status == "success")
            {
                item.GeoLocation = response.countryCode;
                item.ProviderName = response.isp;
                item.TrafficType = AnalyzHeuristics.Analyze(item);
            }
        }
        catch
        {
        }

        return item;
    }

    private class GeoApiResponse
    {
        public string status { get; set; }
        public string countryCode { get; set; }
        public string isp { get; set; }
    }
}
