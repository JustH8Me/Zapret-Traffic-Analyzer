using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace ZapretTraficAnalyz.ViewModels;

public partial class MainViewModel : ObservableObject
{
    [ObservableProperty]
    private object _currentView;

    private GenCfgViewModel _genCfgViewModel =  new GenCfgViewModel();
    private TraficAnalyzViewModel _traficAnalyzViewModel =  new TraficAnalyzViewModel();
    public MainViewModel()
    {

    
        CurrentView  = new TraficAnalyzViewModel();
    }
    [RelayCommand]
    private void GoToScann() => CurrentView = _traficAnalyzViewModel;
    
    [RelayCommand]
    private void GoToGen() => CurrentView = _genCfgViewModel;
}