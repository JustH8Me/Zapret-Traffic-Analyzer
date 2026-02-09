using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Interfaces;

public interface ISnifferService
{
    event Action<TrafficItem> TrafficDetected;
    void Start(string processName);
    void Stop();
}

public interface IFileScannerService
{
    event Action<TrafficItem> ItemFound;
    event Action<string> StatusUpdated;
    Task RunScanAsync(string rootPath);
}

public interface IGeoIpService
{
    Task<TrafficItem> EnrichWithGeoDataAsync(TrafficItem item);
}

public interface IDnsService
{
    Task<List<TrafficItem>> GetDnsCacheAsync();
    Task<string> ResolveHostNameAsync(string ip);
}

public interface INetworkCheckerService
{
    Task<(bool IsAccessible, string Error)> CheckAccessAsync(string ip, string domain, string protocol);
}

public interface IDialogService
{
    void ShowMessage(string message);
    Task<string?> PickFolderAsync();
}

public interface IReportService
{
    void SaveReport(IEnumerable<TrafficItem> items, string mode);
}

public interface IDispatcherService
{
    void Invoke(Action action);
}
