using System.Windows;
using Microsoft.Win32;
using ZapretTraficAnalyz.Interfaces;

namespace ZapretTraficAnalyz.Services;

public class WpfDialogService : IDialogService
{
    public void ShowMessage(string message)
    {
        MessageBox.Show(message);
    }

    public Task<string?> PickFolderAsync()
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Выберите папку"
        };

        if (dialog.ShowDialog() == true)
            return Task.FromResult<string?>(dialog.FolderName);

        return Task.FromResult<string?>(null);
    }
}