using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Data;
using System.Diagnostics;
using System.IO;
using System.Net;
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
    [RelayCommand]
    private void ToggleAllSelection()
    {
        foreach (var item in Items)
        {
            item.IsSelected = IsAllSelected;
        }
    }
    public TraficAnalyzViewModel()
    {
        BindingOperations.EnableCollectionSynchronization(Items, _lock);
        _service.TrafficDetected += item => {
            lock (_lock) 
                if (!Items.Any(x => x.RemoteIP == item.RemoteIP && x.Protocol == item.Protocol)) 
                    Items.Add(item);
        };
    }

    [RelayCommand]
    private async Task CheckAccess()
    {
        var selected = Items.Where(x => x.IsSelected).ToList();
        if (!selected.Any()) return;

        StatusText = "Проверка связи...";
        foreach (var item in selected)
        {
            item.Status = "⏳...";
            var (ok, _) = await NetworkChecker.CheckAsync(item.RemoteIP, item.Domain, item.Protocol);
            item.Status = ok ? "ДОСТУПЕН" : "БЛОК ⛔";
            item.StatusColor = ok ? "Green" : "Red";
        }
        StatusText = "Готово";
    }

    [RelayCommand]
    private async Task ResolveNames()
    {
        var targets = Items.Where(x => x.Domain == "---").ToList();
        StatusText = "Поиск имен...";
        
        await Task.WhenAll(targets.Select(async item => {
            try {
                var entry = await Dns.GetHostEntryAsync(item.RemoteIP);
                if (!string.IsNullOrEmpty(entry.HostName))
                    Application.Current.Dispatcher.Invoke(() => item.Domain = entry.HostName);
            } catch { /* ignored */ }
        }));
        StatusText = "Имена обновлены";
    }

    [RelayCommand]
    private void ToggleScan()
    {
        if (!IsScanning)
        {
            var pids = Process.GetProcessesByName(TargetProcess.Replace(".exe", "")).Select(p => p.Id).ToList();
            if (!pids.Any()) { MessageBox.Show("Процесс не найден!"); return; }

            Process.Start(new ProcessStartInfo("ipconfig", "/flushdns") { CreateNoWindow = true })?.WaitForExit();
            
            Items.Clear();
            _service.Start(pids, TargetProcess);
            (IsScanning, ScanButtonText, StatusText) = (true, "СТОП", "СКАНИРОВАНИЕ...");
        }
        else
        {
            _service.Stop();
            (IsScanning, ScanButtonText, StatusText) = (false, "СТАРТ", "Остановлено");
        }
    }

    [RelayCommand]
    private void SaveToZapret()
    {
        var sel = Items.Where(x => x.IsSelected).ToList();
        if (!sel.Any()) return;

        var path = "zapret-lists";
        Directory.CreateDirectory(path);

        // (1.2.3.4 -> 1.2.3.0/24)
        string ToSubnet(string ip) {
            var parts = ip.Split('.');
            if (parts.Length != 4) return ip;
            return $"{parts[0]}.{parts[1]}.{parts[2]}.0/24";
        }
        
        var domains = sel.Where(x => x.Domain != "---").Select(x => x.Domain).Distinct();
        File.WriteAllLines($"{path}/domains.txt", domains);
        
        var tcpSubnets = sel.Where(x => x.Domain == "---" && x.Protocol == "TCP")
            .Select(x => ToSubnet(x.RemoteIP))
            .Distinct();
        File.WriteAllLines($"{path}/ips-tcp.txt", tcpSubnets);

        var udpSubnets = sel.Where(x => x.Domain == "---" && x.Protocol == "UDP")
            .Select(x => ToSubnet(x.RemoteIP))
            .Distinct();
        File.WriteAllLines($"{path}/ips-udp.txt", udpSubnets);

        MessageBox.Show($"Списки сохранены!\nTCP подсетей: {tcpSubnets.Count()}\nUDP подсетей: {udpSubnets.Count()}");
    }
}