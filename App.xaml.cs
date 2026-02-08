using System.Configuration;
using System.Data;
using System.Windows;
using ZapretTraficAnalyz.ViewModels;

namespace ZapretTraficAnalyz;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        MainWindow window = new MainWindow();
        
        MainViewModel viewModel = new MainViewModel();
        window.DataContext = viewModel;
            
        window.Show();
    }
}