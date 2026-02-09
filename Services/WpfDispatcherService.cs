using System.Windows;
using ZapretTraficAnalyz.Interfaces;

namespace ZapretTraficAnalyz.Services;

public class WpfDispatcherService : IDispatcherService
{
    public void Invoke(Action action)
    {
        Application.Current.Dispatcher.Invoke(action);
    }
}