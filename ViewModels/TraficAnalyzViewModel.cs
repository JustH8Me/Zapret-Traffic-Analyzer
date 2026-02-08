using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Windows;
using System.Windows.Data;
using ZapretTraficAnalyz.Models;
using ZapretTraficAnalyz.Services;

namespace ZapretTraficAnalyz.ViewModels;

public partial class TraficAnalyzViewModel : ObservableObject
{
    private readonly SearchIp _service = new();
    private readonly object _lock = new();

    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private string _targetProcess = "discord.exe"; 
    [ObservableProperty] private string _scanButtonText = "СТАРТ";
    [ObservableProperty] private string _statusText = "Ожидание...";
    [ObservableProperty] private bool _isAllSelected;

    public ObservableCollection<TrafficItem> Items { get; } = [];

    public TraficAnalyzViewModel()
    {
        BindingOperations.EnableCollectionSynchronization(Items, _lock);
        _service.TrafficDetected += OnTrafficDetected;
    }

    private void OnTrafficDetected(TrafficItem newItem)
    {
        lock (_lock)
        {
            var existing = Items.FirstOrDefault(x => x.RemoteIP == newItem.RemoteIP && x.Protocol == newItem.Protocol);

            if (existing == null)
            {
                Application.Current.Dispatcher.Invoke(() => Items.Add(newItem));
            }
            else if (existing.Domain == "---" && newItem.Domain != "---")
            {
                existing.Domain = newItem.Domain;
            }
        }
    }

    [RelayCommand]
    private void ToggleScan()
    {
        if (!IsScanning)
        {
            var procName = TargetProcess.Replace(".exe", "", StringComparison.OrdinalIgnoreCase);
            var pids = Process.GetProcessesByName(procName).Select(p => p.Id).ToList();

            if (pids.Count == 0)
            {
                MessageBox.Show($"Процесс {procName} не найден!");
                return;
            }

            // Очистка DNS
            try { Process.Start(new ProcessStartInfo("ipconfig", "/flushdns") { CreateNoWindow = true }); } catch { }

            Items.Clear();
            _service.Start(TargetProcess);
            
            IsScanning = true;
            ScanButtonText = "СТОП";
            StatusText = $"Сканирую {procName} ({pids.Count} PID)...";
        }
        else
        {
            _service.Stop();
            IsScanning = false;
            ScanButtonText = "СТАРТ";
            StatusText = "Остановлено";
        }
    }
    
    [RelayCommand]
    private void ToggleAllSelection() { foreach(var i in Items) i.IsSelected = IsAllSelected; }

    [RelayCommand]
    private async Task CheckAccess()
    {
        var list = Items.Where(x => x.IsSelected).ToList();
        if(!list.Any()) return;
        StatusText = "Проверка...";
        await Parallel.ForEachAsync(list, async (item, token) => {
             item.Status = "⏳";
             var (ok, _) = await NetworkChecker.CheckAsync(item.RemoteIP, item.Domain, item.Protocol);
             item.Status = ok ? "ДОСТУПЕН" : "БЛОК ⛔";
             item.StatusColor = ok ? "Green" : "Red";
        });
        StatusText = "Готово";
    }

    [RelayCommand]
    private async Task ResolveNames()
    {
        var list = Items.Where(x => x.Domain == "---").ToList();
        StatusText = "Поиск имен...";
        await Task.WhenAll(list.Select(async item => {
            try {
                var e = await Dns.GetHostEntryAsync(item.RemoteIP);
                if(!string.IsNullOrEmpty(e.HostName)) 
                    Application.Current.Dispatcher.Invoke(() => item.Domain = e.HostName);
            } catch { }
        }));
        StatusText = "Имена обновлены";
    }

    [RelayCommand]
    private void Save(string mode)
    {
        var list = mode switch
        {
            "All" => Items.ToList(),                                         
            "Blocked" => Items.Where(x => x.StatusColor == "Red").ToList(),  
            "Ok" => Items.Where(x => x.StatusColor == "Green").ToList(),     
            _ => Items.Where(x => x.IsSelected).ToList()                     
        };

        if (list.Count == 0)
        {
            MessageBox.Show($"В категории '{mode}' пусто!");
            return;
        }
        
        var path = "zapret-lists";
        Directory.CreateDirectory(path);

        string ToSubnet(string ip) 
        {
            var p = ip.Split('.');
            return p.Length == 4 ? $"{p[0]}.{p[1]}.{p[2]}.0/24" : ip;
        }

        var domains = list.Where(x => x.Domain != "---").Select(x => x.Domain).Distinct();
        var tcp = list.Where(x => x.Domain == "---" && x.Protocol == "TCP").Select(x => ToSubnet(x.RemoteIP)).Distinct();
        var udp = list.Where(x => x.Domain == "---" && x.Protocol == "UDP").Select(x => ToSubnet(x.RemoteIP)).Distinct();

        File.WriteAllLines($"{path}/domains.txt", domains);
        File.WriteAllLines($"{path}/ips-tcp.txt", tcp);
        File.WriteAllLines($"{path}/ips-udp.txt", udp);

        MessageBox.Show($"Сохранено ({mode}):\nDomains: {domains.Count()}\nTCP: {tcp.Count()}\nUDP: {udp.Count()}");
    }
}