using CommunityToolkit.Mvvm.ComponentModel;

namespace ZapretTraficAnalyz.Models;

public partial class TrafficItem : ObservableObject
{
    public string Time { get; set; } = "";
    public string Process { get; set; } = "";
    public string RemoteIP { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Protocol { get; set; } = ""; // TCP или UDP

    [ObservableProperty] private bool _isSelected;
    [ObservableProperty] private string _status = "---"; 
    [ObservableProperty] private string _statusColor = "Black";
}