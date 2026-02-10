using Systems_One_Watchdog_Service;
using Serilog;
using Serilog.Events;
using CliWrap;
using CliWrap.Buffered;
using System.Security.Principal;
using System.Runtime.Versioning;

const string ServiceName = "Systems_One_Watchdog_Service";
const string ServiceDisplayName = "Systems One Watchdog Service";
const string ServiceDescription = "Systems One Watchdog Service that monitors and restarts configured applications.";
const string SettingsDirectory = "C:\\Users\\Public\\Documents\\SystemOne_App_Settings";
const string SettingsFileName = "watchdog_settings.json";

[SupportedOSPlatform("windows")]
static bool IsAdministrator()
{
    try
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
    catch
    {
        return false;
    }
}

// Support simple install switch
if (args is { Length: 1 } && string.Equals(args[0], "/Install", StringComparison.OrdinalIgnoreCase))
{
    try
    {
        if (!IsAdministrator())
        {
            Console.WriteLine("Installation requires an elevated (Administrator) command prompt.");
            return;
        }

        // Path to this executable
        string exePath = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
        if (string.IsNullOrWhiteSpace(exePath))
        {
            Console.WriteLine("Unable to determine executable path.");
            return;
        }

        // Ensure settings directory exists and copy default settings
        var settingsDir = SettingsDirectory.Replace('\\', Path.DirectorySeparatorChar);
        var settingsPath = Path.Combine(settingsDir, SettingsFileName);
        Directory.CreateDirectory(settingsDir);

        var sourceAppSettings = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        try
        {
            if (File.Exists(sourceAppSettings))
            {
                if (!File.Exists(settingsPath))
                {
                    File.Copy(sourceAppSettings, settingsPath);
                    Console.WriteLine($"Copied settings to {settingsPath}");
                }
                else
                {
                    Console.WriteLine($"Settings file already exists at {settingsPath}; leaving it unchanged.");
                }
            }
            else
            {
                Console.WriteLine($"Source appsettings.json not found at {sourceAppSettings}; no settings were copied.");
            }
        }
        catch (Exception copyEx)
        {
            Console.WriteLine($"Failed to copy settings: {copyEx}");
        }

        // sc.exe create <ServiceName> binPath= "<path>" start= auto type= own DisplayName= "..."
        await Cli.Wrap("sc")
            .WithArguments(new[]
            {
                "create", ServiceName,
                "binPath=", exePath,
                "start=", "auto",
                "type=", "own",
                "DisplayName=", ServiceDisplayName
            })
            .ExecuteAsync();

        // sc.exe description <ServiceName> "<description>"
        await Cli.Wrap("sc")
            .WithArguments(new[] { "description", ServiceName, ServiceDescription })
            .ExecuteAsync();

        // Verify registration
        var result = await Cli.Wrap("sc")
            .WithArguments(new[] { "query", ServiceName })
            .ExecuteBufferedAsync();

        Console.WriteLine(result.StandardOutput);
        Console.WriteLine($"Service '{ServiceName}' created with binPath=\"{exePath}\" and DisplayName=\"{ServiceDisplayName}\"\nDescription set to: {ServiceDescription}");
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex);
    }

    return;
}

// Support simple uninstall switch
if (args is { Length: 1 } && string.Equals(args[0], "/Uninstall", StringComparison.OrdinalIgnoreCase))
{
    try
    {
        if (!IsAdministrator())
        {
            Console.WriteLine("Uninstall requires an elevated (Administrator) command prompt.");
            return;
        }

        // Try to stop the service (ignore errors if not running/not installed)
        try { await Cli.Wrap("sc").WithArguments(new[] { "stop", ServiceName }).ExecuteAsync(); } catch { }
        await Task.Delay(TimeSpan.FromSeconds(2));
        await Cli.Wrap("sc").WithArguments(new[] { "delete", ServiceName }).ExecuteAsync();
        Console.WriteLine($"Service '{ServiceName}' deleted.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to uninstall service: {ex}");
    }

    return;
}

// Ensure a minimal bootstrap logger before configuration is read
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .WriteTo.Console()
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);

    // Ensure service integration
    builder.Services.AddWindowsService(options =>
    {
        options.ServiceName = ServiceName;
    });

    // Set content root to executable directory when running as a service
    var exeDir = AppContext.BaseDirectory;
    builder.Environment.ContentRootPath = exeDir;

    // External settings file override
    var externalSettingsDir = SettingsDirectory.Replace('\\', Path.DirectorySeparatorChar);
    var externalSettingsPath = Path.Combine(externalSettingsDir, SettingsFileName);
    builder.Configuration.AddJsonFile(externalSettingsPath, optional: true, reloadOnChange: true);

    // Bind monitoring options
    builder.Services.Configure<MonitorOptions>(builder.Configuration.GetSection("Monitor"));
    var monitor = new MonitorOptions();
    builder.Configuration.GetSection("Monitor").Bind(monitor);

    Log.Information("Config loaded. External settings path: {Path} Exists: {Exists}", externalSettingsPath, File.Exists(externalSettingsPath));

    // Configure logging based on settings
    if (monitor.Logging?.EnableFileLogging == true)
    {
        var logPath = string.IsNullOrWhiteSpace(monitor.Logging.LogFilePath)
            ? Path.Combine(externalSettingsDir, "logs", "watchdog.log")
            : monitor.Logging.LogFilePath;

        var level = monitor.Logging.LogLevel?.ToLowerInvariant() switch
        {
            "trace" => LogEventLevel.Verbose,
            "debug" => LogEventLevel.Debug,
            "information" => LogEventLevel.Information,
            "warning" => LogEventLevel.Warning,
            "error" => LogEventLevel.Error,
            "critical" or "fatal" => LogEventLevel.Fatal,
            _ => LogEventLevel.Information
        };

        try
        {
            var dir = Path.GetDirectoryName(logPath);
            if (!string.IsNullOrWhiteSpace(dir))
                Directory.CreateDirectory(dir);
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to ensure log directory exists: {Dir}", logPath);
        }

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Is(level)
            .Enrich.FromLogContext()
            .WriteTo.File(
                logPath!,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: monitor.Logging.RetainedFileCountLimit,
                shared: true)
            .WriteTo.Console()
            .CreateLogger();

        builder.Logging.ClearProviders();
        builder.Logging.AddSerilog(Log.Logger, dispose: true);

        Log.Information("File logging configured at {LogPath} level {Level}", logPath, level);
    }

    builder.Services.AddHostedService<Worker>();

    var host = builder.Build();
    host.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Service failed to start");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
