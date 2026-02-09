using System.Collections.ObjectModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Models;
using ZapretTraficAnalyz.Services;

namespace ZapretTraficAnalyz.ViewModels;

public partial class TraficAnalyzViewModel : ObservableObject
{
    private readonly IDialogService _dialogService;
    private readonly IDispatcherService _dispatcher;
    private readonly IDnsService _dnsService;
    private readonly IFileScannerService _fileScannerService;
    private readonly IGeoIpService _geoIpService;

    private readonly INetworkCheckerService _networkChecker;
    private readonly IReportService _reportService;
    private readonly ISnifferService _snifferService;
    private readonly object _lock = new();
    [ObservableProperty] private bool _isAllSelected;


    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private string _scanButtonText = "СТАРТ";
    [ObservableProperty] private string _statusText = "Готов к работе";
    [ObservableProperty] private string _targetProcess = "r5apex.exe";


    public TraficAnalyzViewModel(
        ISnifferService snifferService,
        IFileScannerService fileScannerService,
        IGeoIpService geoIpService,
        IDnsService dnsService,
        INetworkCheckerService networkChecker,
        IDialogService dialogService,
        IReportService reportService,
        IDispatcherService dispatcher)
    {
        _snifferService = snifferService;
        _fileScannerService = fileScannerService;
        _geoIpService = geoIpService;
        _dnsService = dnsService;
        _networkChecker = networkChecker;
        _dialogService = dialogService;
        _reportService = reportService;
        _dispatcher = dispatcher;
        BindingOperations.EnableCollectionSynchronization(Items, _lock);

        SubscribeEvents();
    }

    public ObservableCollection<TrafficItem> Items { get; } = new();

    private void SubscribeEvents()
    {
        _snifferService.TrafficDetected += newItem =>
        {
            lock (_lock)
            {
                var existing =
                    Items.FirstOrDefault(x => x.RemoteIP == newItem.RemoteIP && x.Protocol == newItem.Protocol);

                if (existing == null)
                {
                    newItem.TrafficType = AnalyzHeuristics.Analyze(newItem);

                    _dispatcher.Invoke(() => Items.Add(newItem));

                    _ = EnrichItemAsync(newItem);
                }
                else
                {
                    existing.PacketCount++;
                    existing.Time = DateTime.Now.ToString("HH:mm:ss");

                    if (existing.Domain == "---" && newItem.Domain != "---")
                    {
                        existing.Domain = newItem.Domain;

                        existing.TrafficType = AnalyzHeuristics.Analyze(existing);
                    }
                }
            }
        };


        _fileScannerService.ItemFound += item => _dispatcher.Invoke(() =>
        {
            lock (_lock)
            {
                Items.Add(item);
            }
        });

        _fileScannerService.StatusUpdated += status => _dispatcher.Invoke(() => StatusText = status);
    }

    private async Task EnrichItemAsync(TrafficItem item)
    {
        await _geoIpService.EnrichWithGeoDataAsync(item);
        _dispatcher.Invoke(() => item.TrafficType = AnalyzHeuristics.Analyze(item));
    }

    [RelayCommand]
    private void ToggleScan()
    {
        if (string.IsNullOrWhiteSpace(TargetProcess))
        {
            _dialogService.ShowMessage("Укажите имя процесса!");
            return;
        }

        if (!IsScanning)
        {
            lock (_lock)
            {
                var toRemove = Items.Where(x => x.Status != "Files" && x.Status != "Cached").ToList();
                foreach (var item in toRemove) Items.Remove(item);
            }

            _snifferService.Start(TargetProcess);
            IsScanning = true;
            ScanButtonText = "СТОП";
            StatusText = $"Сниффинг: {TargetProcess}";
        }
        else
        {
            _snifferService.Stop();
            IsScanning = false;
            ScanButtonText = "СТАРТ";
            StatusText = "Остановлено";
        }
    }

    [RelayCommand]
    private async Task StaticScan()
    {
        var folder = await _dialogService.PickFolderAsync();
        if (string.IsNullOrEmpty(folder)) return;

        lock (_lock)
        {
            var fileItems = Items.Where(x => x.Status == "Files").ToList();
            foreach (var item in fileItems) Items.Remove(item);
        }

        await _fileScannerService.RunScanAsync(folder);
    }

    [RelayCommand]
    private async Task LoadDnsCache()
    {
        StatusText = "Загрузка DNS кэша...";
        var cacheItems = await _dnsService.GetDnsCacheAsync();
        _dispatcher.Invoke(() =>
        {
            foreach (var item in cacheItems)
                if (!Items.Any(x => x.Domain == item.Domain))
                    Items.Add(item);
            StatusText = $"DNS Кэш: {cacheItems.Count} записей";
        });
    }

    [RelayCommand]
    private async Task CheckAccess()
    {
        var list = Items.Where(x => x.RemoteIP != "FILE" && x.RemoteIP != "DNS Cache").ToList();
        if (!list.Any()) return;

        StatusText = $"Проверка {list.Count} адресов...";

        await Parallel.ForEachAsync(list, new ParallelOptions { MaxDegreeOfParallelism = 10 }, async (item, token) =>
        {
            _dispatcher.Invoke(() => item.Status = "Checking...");

            var result = await _networkChecker.CheckAccessAsync(item.RemoteIP, item.Domain, item.Protocol);

            _dispatcher.Invoke(() =>
            {
                item.Status = result.IsAccessible ? "Access OK" : "BLOCKED";
                item.StatusColor = result.IsAccessible ? "#2ECC71" : "#E74C3C";
            });
        });

        StatusText = "Проверка завершена";
    }

    [RelayCommand]
    private async Task ResolveNames()
    {
        var list = Items.Where(x => x.Domain == "---" && x.RemoteIP.Contains(".")).ToList();
        StatusText = "Resolving DNS...";

        await Parallel.ForEachAsync(list, new ParallelOptions { MaxDegreeOfParallelism = 5 }, async (item, _) =>
        {
            var host = await _dnsService.ResolveHostNameAsync(item.RemoteIP);
            if (!string.IsNullOrEmpty(host))
                _dispatcher.Invoke(() => item.Domain = host);
        });
        StatusText = "Имена обновлены";
    }

    [RelayCommand]
    private void Save(string mode)
    {
        var list = mode switch
        {
            "All" => Items,
            "Blocked" => Items.Where(x => x.StatusColor == "#E74C3C"),
            "Ok" => Items.Where(x => x.StatusColor == "#2ECC71"),
            _ => Items.Where(x => x.IsSelected)
        };

        if (!list.Any())
        {
            _dialogService.ShowMessage("Список пуст!");
            return;
        }

        _reportService.SaveReport(list, mode);
        _dialogService.ShowMessage("Сохранено!");
    }

    [RelayCommand]
    private void ToggleAllSelection()
    {
        foreach (var i in Items) i.IsSelected = IsAllSelected;
    }
}
