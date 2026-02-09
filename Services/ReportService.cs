using System.IO;
using ZapretTraficAnalyz.Interfaces;
using ZapretTraficAnalyz.Models;

namespace ZapretTraficAnalyz.Services;

public class ReportService : IReportService
{
    public void SaveReport(IEnumerable<TrafficItem> items, string mode)
    {
        var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "zapret-lists");
        Directory.CreateDirectory(path);

        var list = items.ToList();
        var domains = list.Where(x => x.Domain != "---" && x.Domain.Contains(".")).Select(x => x.Domain).Distinct();

        File.WriteAllLines(Path.Combine(path, $"export_{mode}_domains.txt"), domains);
    }
}
