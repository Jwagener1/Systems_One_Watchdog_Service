namespace Systems_One_Watchdog_Service;

public sealed class MonitorOptions
{
    public int PollSeconds { get; set; } = 5;
    public List<MonitorApp> Apps { get; set; } = new();
    public MonitorLoggingOptions Logging { get; set; } = new();
}

public sealed class MonitorApp
{
    public string? Name { get; set; }
    public string? Exe { get; set; }
    public string? Args { get; set; }
    public string? WorkingDir { get; set; }
    public bool OnlyOneInstance { get; set; } = true;
    public bool AutoRestart { get; set; } = true;
}

public sealed class MonitorLoggingOptions
{
    public bool EnableFileLogging { get; set; }
    public string? LogFilePath { get; set; }
    public string? LogLevel { get; set; } = "Information";
    public int RetainedFileCountLimit { get; set; } = 7;
}
