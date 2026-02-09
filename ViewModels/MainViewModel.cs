using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ZapretTraficAnalyz.ViewModels;

public partial class MainViewModel : ObservableObject
{
    private readonly GenCfgViewModel _genCfgViewModel;
    private readonly TraficAnalyzViewModel _traficAnalyzViewModel;

    [ObservableProperty] private object _currentView;

    public MainViewModel(TraficAnalyzViewModel traficAnalyzViewModel, GenCfgViewModel genCfgViewModel)
    {
        _traficAnalyzViewModel = traficAnalyzViewModel;
        _genCfgViewModel = genCfgViewModel;
        CurrentView = _traficAnalyzViewModel;
    }

    [RelayCommand]
    private void GoToScann()
    {
        CurrentView = _traficAnalyzViewModel;
    }

    [RelayCommand]
    private void GoToGen()
    {
        CurrentView = _genCfgViewModel;
    }
}
