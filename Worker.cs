using System.Diagnostics;
using Microsoft.Extensions.Options;

namespace Systems_One_Watchdog_Service
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly IOptionsMonitor<MonitorOptions> _optionsMonitor;

        // Track restart failures per app for exponential backoff
        private readonly Dictionary<string, AppRestartState> _restartStates = new();

        public Worker(ILogger<Worker> logger, IOptionsMonitor<MonitorOptions> optionsMonitor)
        {
            _logger = logger;
            _optionsMonitor = optionsMonitor;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var options = _optionsMonitor.CurrentValue;

            if (options.Apps == null || options.Apps.Count == 0)
            {
                _logger.LogWarning("No apps configured to monitor.");
                return;
            }

            // Validate configuration at startup
            ValidateConfiguration(options);

            _logger.LogInformation("Watchdog started. Monitoring {Count} app(s).", options.Apps.Count);

            while (!stoppingToken.IsCancellationRequested)
            {
                // Re-read options to support config reload
                options = _optionsMonitor.CurrentValue;

                try
                {
                    foreach (var app in options.Apps)
                    {
                        await MonitorAppAsync(app, options, stoppingToken);
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

                var interval = TimeSpan.FromSeconds(Math.Max(1, options.PollSeconds));
                await Task.Delay(interval, stoppingToken);
            }
        }

        private void ValidateConfiguration(MonitorOptions options)
        {
            foreach (var app in options.Apps)
            {
                foreach (var error in app.Validate())
                {
                    _logger.LogWarning("Configuration warning: {Error}", error);
                }
            }
        }

        private string GetAppKey(MonitorApp app) => app.Exe?.ToLowerInvariant() ?? app.Name ?? "unknown";

        private AppRestartState GetOrCreateRestartState(MonitorApp app)
        {
            var key = GetAppKey(app);
            if (!_restartStates.TryGetValue(key, out var state))
            {
                state = new AppRestartState();
                _restartStates[key] = state;
            }
            return state;
        }

        private async Task MonitorAppAsync(MonitorApp app, MonitorOptions options, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(app.Exe))
            {
                _logger.LogWarning("App '{Name}' has no 'Exe' configured.", app.Name);
                return;
            }

            var procName = Path.GetFileNameWithoutExtension(app.Exe);
            var processes = Process.GetProcessesByName(procName);

            try
            {
                bool isRunning = processes.Length > 0;
                var restartState = GetOrCreateRestartState(app);

                if (isRunning)
                {
                    if (app.OnlyOneInstance)
                    {
                        _logger.LogDebug("App '{Name}' is running (PID(s): {Pids}).", app.Name, string.Join(",", processes.Select(p => p.Id)));
                    }

                    // Reset failure count when app is running successfully
                    restartState.ConsecutiveFailures = 0;
                    restartState.NextRestartAllowed = DateTime.MinValue;
                    return;
                }

                if (!app.AutoRestart)
                {
                    return;
                }

                // Check if we've exceeded max consecutive failures
                if (options.MaxConsecutiveFailures > 0 && restartState.ConsecutiveFailures >= options.MaxConsecutiveFailures)
                {
                    if (!restartState.DisabledLogged)
                    {
                        _logger.LogError("App '{Name}' has failed {Count} consecutive times. Auto-restart disabled until service restart or app runs successfully.",
                            app.Name, restartState.ConsecutiveFailures);
                        restartState.DisabledLogged = true;
                    }
                    return;
                }

                // Check backoff timer
                if (DateTime.UtcNow < restartState.NextRestartAllowed)
                {
                    _logger.LogDebug("App '{Name}' restart delayed until {Time} (backoff).", app.Name, restartState.NextRestartAllowed.ToLocalTime());
                    return;
                }

                _logger.LogWarning("App '{Name}' is not running. Attempting restart (attempt {Attempt})...",
                    app.Name, restartState.ConsecutiveFailures + 1);

                // Short debounce to avoid thrash
                await Task.Delay(TimeSpan.FromSeconds(1), ct);
                if (Process.GetProcessesByName(procName).Length > 0)
                {
                    _logger.LogInformation("App '{Name}' started by another source.", app.Name);
                    return;
                }

                // Verify executable exists before attempting restart
                if (!File.Exists(app.Exe))
                {
                    _logger.LogError("App '{Name}' executable not found: {Exe}. Skipping restart.", app.Name, app.Exe);
                    restartState.ConsecutiveFailures++;
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

                    // Reset failure state on successful start
                    restartState.ConsecutiveFailures = 0;
                    restartState.DisabledLogged = false;
                }
                catch (Exception ex)
                {
                    restartState.ConsecutiveFailures++;

                    // Calculate exponential backoff delay
                    var backoffSeconds = Math.Min(
                        options.InitialRestartDelaySeconds * Math.Pow(2, restartState.ConsecutiveFailures - 1),
                        options.MaxRestartDelaySeconds);
                    restartState.NextRestartAllowed = DateTime.UtcNow.AddSeconds(backoffSeconds);

                    _logger.LogError(ex, "Failed to start app '{Name}' ({Exe}). Next retry in {Delay}s (failure {Count}/{Max})",
                        app.Name, app.Exe, backoffSeconds, restartState.ConsecutiveFailures,
                        options.MaxConsecutiveFailures > 0 ? options.MaxConsecutiveFailures.ToString() : "unlimited");
                }
            }
            finally
            {
                // Dispose process handles to avoid resource leaks
                foreach (var p in processes)
                {
                    p.Dispose();
                }
            }
        }

        /// <summary>
        /// Tracks restart state for exponential backoff and failure limiting.
        /// </summary>
        private class AppRestartState
        {
            public int ConsecutiveFailures { get; set; }
            public DateTime NextRestartAllowed { get; set; } = DateTime.MinValue;
            public bool DisabledLogged { get; set; }
        }
    }
}
