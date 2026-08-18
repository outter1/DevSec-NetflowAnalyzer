; Script do Inno Setup para o DevSec - NetFlow Analyzer
; Compile com o Inno Setup Compiler (jrsoftware.org) depois de gerar dist\DevSec com o PyInstaller.

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
; Descomente e aponte para um .ico real quando tiver um:
; SetupIconFile=assets\logos\devsec.ico

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Files]
; Copia tudo que o PyInstaller gerou em modo pasta (--onedir).
; Se usar --onefile, troque por: Source: "dist\DevSec.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\DevSec\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\DevSec NetFlow Analyzer"; Filename: "{app}\DevSec.exe"
Name: "{group}\Desinstalar DevSec"; Filename: "{uninstallexe}"
Name: "{autodesktop}\DevSec NetFlow Analyzer"; Filename: "{app}\DevSec.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Criar atalho na área de trabalho"; GroupDescription: "Atalhos adicionais:"

[Run]
; Abre o app ao final da instalação (opcional).
Filename: "{app}\DevSec.exe"; Description: "Abrir DevSec agora"; Flags: nowait postinstall skipifsilent

; Se você optar por embutir e rodar o instalador do Npcap automaticamente,
; baixe o instalador oficial (npcap-x.xx.exe) no site do Npcap, coloque-o em
; uma pasta "redist\" do projeto e descomente as linhas abaixo. Antes disso,
; confira a licença do Npcap para redistribuição.
; [Files]
; Source: "redist\npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall
; [Run]
; Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S"; StatusMsg: "Instalando Npcap..."; Flags: waituntilterminated
