#define AppName "RIZVI WAF"
#define AppVersion "1.0.0"
#define AppPublisher "Ch Abdul Rehman Bajwa"
#define AppExeName "RIZVI WAF.exe"
#define ProjectRoot AddBackslash(SourcePath) + ".."

[Setup]
AppId={{01AB2C73-199B-4A4D-9CC0-8A55C5E7A110}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
MinVersion=10.0.10240
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#ProjectRoot}\dist\installer
OutputBaseFilename=RIZVI-WAF-Setup-{#AppVersion}
SetupIconFile={#ProjectRoot}\installer\RIZVI-WAF.ico
WizardImageFile={#ProjectRoot}\installer\wizard.bmp
WizardSmallImageFile={#ProjectRoot}\installer\wizard-small.bmp
UninstallDisplayIcon={app}\{#AppExeName}
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=RIZVI WAF Setup
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "{#ProjectRoot}\dist\RIZVI WAF\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
