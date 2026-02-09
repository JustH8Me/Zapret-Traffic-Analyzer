using System.Windows;
using CommunityToolkit.Mvvm.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Services;
using ZapretTraficAnalyz.ViewModels;

namespace ZapretTraficAnalyz;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);


        var services = new ServiceCollection();


        services.AddSingleton<ISnifferService, SearchIp>();
        services.AddSingleton<IFileScannerService, ScanFile>();
        services.AddSingleton<IGeoIpService, GeoIpService>();
        services.AddSingleton<IDnsService, DnsService>();
        services.AddSingleton<INetworkCheckerService, NetworkCheckerService>();
        services.AddSingleton<IDialogService, WpfDialogService>();
        services.AddSingleton<IReportService, ReportService>();
        services.AddSingleton<IDispatcherService, WpfDispatcherService>();


        services.AddSingleton<GenCfgViewModel>();
        services.AddSingleton<TraficAnalyzViewModel>();
        services.AddSingleton<MainViewModel>();

        var serviceProvider = services.BuildServiceProvider();


        Ioc.Default.ConfigureServices(serviceProvider);


        var mainViewModel = Ioc.Default.GetService<MainViewModel>();


        var window = new MainWindow { DataContext = mainViewModel };
        window.Show();
    }
}