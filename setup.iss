#define MyAppName "Systems One Watchdog Service"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Systems One"
#define MyAppExeName "Systems_One_Watchdog_Service.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=installer_output
OutputBaseFilename=Systems_One_Watchdog_Service_Setup
SetupIconFile=systems_one.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
; Require admin rights to install a Windows service
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Include all published output files
Source: "publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
; Install as a Windows Service after setup
Filename: "sc.exe"; Parameters: "create ""{#MyAppName}"" binPath=""{app}\{#MyAppExeName}"" start=auto"; \
  Flags: runhidden; StatusMsg: "Installing Windows Service..."
Filename: "sc.exe"; Parameters: "start ""{#MyAppName}"""; \
  Flags: runhidden; StatusMsg: "Starting Windows Service..."

[UninstallRun]
; Stop and remove the Windows Service on uninstall
Filename: "sc.exe"; Parameters: "stop ""{#MyAppName}"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete ""{#MyAppName}"""; Flags: runhidden
