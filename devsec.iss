; Script do Inno Setup para o DevSec - NetFlow Analyzer

[Setup]
AppId={{B6E4B6C0-3F7C-4C7A-9A0E-DEVSEC000001}}
AppName=DevSec NetFlow Analyzer
AppVersion=1.0.0
AppPublisher=KillChain
DefaultDirName={autopf}\DevSec NetFlow Analyzer
DefaultGroupName=DevSec NetFlow Analyzer
OutputDir=installer_output
OutputBaseFilename=DevSecSetup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

; Ícone do instalador (DevSecSetup.exe)
SetupIconFile=assets\logos\devsec.ico

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; GroupDescription: "Atalhos adicionais:"

[Files]
; Executável gerado na pasta dist
Source: "dist\DevSec.exe"; DestDir: "{app}"; Flags: ignoreversion

; Instalador do Npcap
Source: "redist\npcap-1.88.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
; Os atalhos usarão automaticamente o ícone embutido no DevSec.exe pelo PyInstaller
Name: "{group}\DevSec NetFlow Analyzer"; Filename: "{app}\DevSec.exe"; IconFilename: "{app}\DevSec.exe"
Name: "{group}\Desinstalar DevSec"; Filename: "{uninstallexe}"
Name: "{autodesktop}\DevSec NetFlow Analyzer"; Filename: "{app}\DevSec.exe"; Tasks: desktopicon; IconFilename: "{app}\DevSec.exe"

[Run]
; 1. Instalação silenciosa do Npcap
Filename: "{tmp}\npcap-1.88.exe"; Parameters: "/S"; StatusMsg: "Instalando Npcap..."; Flags: waituntilterminated

; 2. Abrir o app ao concluir
Filename: "{app}\DevSec.exe"; Description: "Abrir DevSec agora"; Flags: nowait postinstall skipifsilent