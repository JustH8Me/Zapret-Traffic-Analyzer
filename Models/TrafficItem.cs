using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
// Нужно для цветов (Brushes)

namespace ZapretTraficAnalyz.Models;

public partial class TrafficItem : ObservableObject
{
    // --- Существующие Observable поля ---

    [ObservableProperty] private string _domain = "---";

    [ObservableProperty] private string _geoLocation = ""; // Например: "Frankfurt, DE"

    [ObservableProperty] private bool _isSelected;

    // 2. Статистика пакетов (для эвристики)
    [ObservableProperty] private long _packetCount = 1;

    // --- НОВЫЕ ПОЛЯ (Для Smart Labeling и Heuristics) ---

    // 1. Провайдер и Гео (ASN / GeoIP)
    [ObservableProperty] private string _providerName = "Analyzing..."; // Например: "Amazon AWS", "Valve Corp"

    [ObservableProperty] private string _status = "Wait"; // Wait, Allowed, Blocked

    [ObservableProperty] private string _statusColor = "Gray"; // Цвет статуса (текстом или Hex)

    // 3. Тип трафика (Геймплей, Войс, Лобби)
    // Атрибут NotifyPropertyChangedFor автоматически уведомит UI об обновлении зависимых свойств
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasTrafficType))]
    [NotifyPropertyChangedFor(nameof(TrafficTypeColorBrush))]
    private string _trafficType = "";

    // Стандартные поля (меняются редко или один раз при создании)
    public string Time { get; set; } = DateTime.Now.ToString("HH:mm:ss");
    public string Process { get; set; } = "";
    public string RemoteIP { get; set; } = "";
    public string Protocol { get; set; } = ""; // TCP или UDP

    // --- ВЫЧИСЛЯЕМЫЕ СВОЙСТВА (Для UI) ---

    // Скрывает бейджик типа трафика, если он не определен
    public bool HasTrafficType =>
        !string.IsNullOrEmpty(TrafficType) && TrafficType != "UNKNOWN" && TrafficType != "---";

    // Возвращает цвет плашки в зависимости от типа трафика
    public Brush TrafficTypeColorBrush
    {
        get
        {
            return TrafficType switch
            {
                "GAMEPLAY" => Brushes.LimeGreen, // Ярко-зеленый для игры
                "VOIP" => Brushes.DeepSkyBlue, // Синий для голоса
                "LOBBY" => Brushes.Orange, // Оранжевый для меню/магазина
                "WEB" => Brushes.Gray, // Серый для картинок/новостей
                _ => Brushes.Transparent
            };
        }
    }
}