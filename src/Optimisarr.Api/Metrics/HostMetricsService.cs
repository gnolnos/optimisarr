using System.Runtime.InteropServices;

namespace Optimisarr.Api.Metrics;

/// <summary>
/// Whole-host CPU and GPU load for the server's own card in the Workers view. Sampled live and
/// continuously — independently of any encode — so an operator sees the machine that is running
/// the server under all conditions, not only while ffmpeg is busy. Only unprivileged sources are
/// read (like the sidecar's LinuxSystemMetrics): a null reading means unavailable, never idle.
/// </summary>
public sealed class HostMetricsService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(2);
    private readonly LinuxSystemMetrics _metrics = new();
    private double? _cpuPercent;
    private double? _gpuPercent;
    private string? _gpuEngine;

    public double? CpuPercent => _cpuPercent;
    public double? GpuPercent => _gpuPercent;
    public string? GpuEngine => _gpuEngine;
    public string HostName { get; } = Environment.MachineName;
    public string OperatingSystem { get; } = RuntimeInformation.OSDescription;
    public string Architecture { get; } = RuntimeInformation.OSArchitecture.ToString();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Prime the CPU baseline so the first published reading is already finite, not null.
        _metrics.ReadCpu();

        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                _cpuPercent = _metrics.ReadCpu();
                var gpu = await _metrics.ReadSystemGpuAsync(stoppingToken);
                _gpuPercent = gpu?.Percent;
                _gpuEngine = gpu?.Engine;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
                // Telemetry must never take the host down.
            }
        }
    }
}
