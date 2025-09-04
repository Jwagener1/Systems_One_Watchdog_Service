namespace Systems_One_Watchdog_Service;

public sealed class WatchdogOptions
{
    public string? ExecutablePath { get; set; }
    public string? Arguments { get; set; }
    public int CheckIntervalSeconds { get; set; } = 5;
    public int RestartDelaySeconds { get; set; } = 2;
    public bool EnsureSingleInstance { get; set; } = true;
}
