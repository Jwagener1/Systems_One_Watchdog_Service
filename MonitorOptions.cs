namespace Systems_One_Watchdog_Service;

public sealed class MonitorOptions
{
    public int PollSeconds { get; set; } = 5;
    public List<MonitorApp> Apps { get; set; } = new();
    public MonitorLoggingOptions Logging { get; set; } = new();

    /// <summary>
    /// Maximum consecutive restart failures before disabling auto-restart for an app.
    /// Set to 0 to disable this feature.
    /// </summary>
    public int MaxConsecutiveFailures { get; set; } = 5;

    /// <summary>
    /// Initial delay in seconds before attempting a restart after failure.
    /// Used for exponential backoff.
    /// </summary>
    public int InitialRestartDelaySeconds { get; set; } = 2;

    /// <summary>
    /// Maximum delay in seconds between restart attempts (caps exponential backoff).
    /// </summary>
    public int MaxRestartDelaySeconds { get; set; } = 60;
}

public sealed class MonitorApp
{
    public string? Name { get; set; }
    public string? Exe { get; set; }
    public string? Args { get; set; }
    public string? WorkingDir { get; set; }
    public bool OnlyOneInstance { get; set; } = true;
    public bool AutoRestart { get; set; } = true;

    /// <summary>
    /// Validates the configuration and returns any validation errors.
    /// </summary>
    public IEnumerable<string> Validate()
    {
        if (string.IsNullOrWhiteSpace(Exe))
            yield return $"App '{Name ?? "(unnamed)"}' has no 'Exe' configured.";
        else if (!File.Exists(Exe))
            yield return $"App '{Name ?? "(unnamed)"}' executable not found: {Exe}";

        if (!string.IsNullOrWhiteSpace(WorkingDir) && !Directory.Exists(WorkingDir))
            yield return $"App '{Name ?? "(unnamed)"}' working directory not found: {WorkingDir}";
    }
}

public sealed class MonitorLoggingOptions
{
    public bool EnableFileLogging { get; set; }
    public string? LogFilePath { get; set; }
    public string? LogLevel { get; set; } = "Information";
    public int RetainedFileCountLimit { get; set; } = 7;
}
