; Inno Setup script: dist\AISOCPlatform -> one setup .exe (built by build_desktop.ps1)
#define AppName "AI SOC Platform"
#define AppVersion "2.0.0"
#define AppPublisher "Abhinav"
#define AppExe "AISOCPlatform.exe"

[Setup]
AppId={{3E5B9C2A-7D41-4F6B-9A0E-2C8D51F4B7A3}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL=https://github.com/Abhinav-836/ai-soc-platform
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\dist
OutputBaseFilename=AISOCPlatform-Setup-{#AppVersion}
SetupIconFile=assets\app.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\AISOCPlatform\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{#AppName} (with live simulation)"; Filename: "{app}\{#AppExe}"; Parameters: "--simulate"
Name: "{group}\{#AppName} data folder"; Filename: "{localappdata}\AISOCPlatform"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Parameters: "--simulate"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

; Data (database, logs, model, your rules) lives in %LOCALAPPDATA%\AISOCPlatform and is kept on uninstall.
