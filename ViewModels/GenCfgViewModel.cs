using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
namespace ZapretTraficAnalyz.ViewModels;

public partial class GenCfgViewModel : ObservableObject
{
    [ObservableProperty]
    private string _strategy = "--dpi-desync=fake --dpi-desync-ttl=3"; // Пример стратегии

    [ObservableProperty]
    private string _resultList = "api.game.com\nauth.game.com\ncdn.update.net"; // Список доменов

    [RelayCommand]
    private void CreateBatFile()
    {
        // Логика сохранения
    }
}