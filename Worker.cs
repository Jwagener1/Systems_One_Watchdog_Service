using System.Diagnostics;
using Microsoft.Extensions.Options;

namespace Systems_One_Watchdog_Service
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly MonitorOptions _options;

        public Worker(ILogger<Worker> logger, IOptions<MonitorOptions> options)
        {
            _logger = logger;
            _options = options.Value;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (_options.Apps == null || _options.Apps.Count == 0)
            {
                _logger.LogWarning("No apps configured to monitor.");
                return;
            }

            _logger.LogInformation("Watchdog started. Monitoring {Count} app(s).", _options.Apps.Count);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    foreach (var app in _options.Apps)
                    {
                        await MonitorAppAsync(app, stoppingToken);
                    }
                }
                catch (OperationCanceledException)
                {
                    // shutting down
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error in watchdog loop");
                }

                var interval = TimeSpan.FromSeconds(Math.Max(1, _options.PollSeconds));
                await Task.Delay(interval, stoppingToken);
            }
        }

        private async Task MonitorAppAsync(MonitorApp app, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(app.Exe))
            {
                _logger.LogWarning("App '{Name}' has no 'Exe' configured.", app.Name);
                return;
            }

            var procName = Path.GetFileNameWithoutExtension(app.Exe);
            var processes = Process.GetProcessesByName(procName);
            bool isRunning = processes.Any();

            if (isRunning && app.OnlyOneInstance)
            {
                // Already running, nothing to do
                _logger.LogDebug("App '{Name}' is running (PID(s): {Pids}).", app.Name, string.Join(",", processes.Select(p => p.Id)));
                return;
            }

            if (!isRunning && app.AutoRestart)
            {
                _logger.LogWarning("App '{Name}' is not running. Attempting restart...", app.Name);

                // Short debounce to avoid thrash
                await Task.Delay(TimeSpan.FromSeconds(1), ct);
                if (Process.GetProcessesByName(procName).Any())
                {
                    _logger.LogInformation("App '{Name}' started by another source.", app.Name);
                    return;
                }

                try
                {
                    var p = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = app.Exe!,
                            Arguments = app.Args ?? string.Empty,
                            WorkingDirectory = string.IsNullOrWhiteSpace(app.WorkingDir) ? string.Empty : app.WorkingDir,
                            UseShellExecute = false
                        }
                    };

                    p.StartAsActiveUser();
                    _logger.LogInformation("Started app '{Name}' ({Exe})", app.Name, app.Exe);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to start app '{Name}' ({Exe})", app.Name, app.Exe);
                }
            }
        }
    }
}
