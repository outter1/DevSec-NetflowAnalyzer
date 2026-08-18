# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        # Templates usados pela interface web (app_web.py também os importa
        # indiretamente via ui/, então incluir aqui evita erro de "template not found").
        ('ui/templates', 'ui/templates'),
        # Logos/ícones do projeto. Se a pasta estiver vazia, o PyInstaller ainda
        # aceita o diretório; remova esta linha se não for usar nada daqui.
        ('assets', 'assets'),
    ],
    hiddenimports=[
        # O Scapy carrega vários submódulos dinamicamente conforme o SO,
        # e o PyInstaller não detecta isso sozinho.
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.layers.l2',
        'scapy.layers.dns',
        'scapy.layers.tls.all',
        'scapy.arch.windows',
        # CustomTkinter às vezes precisa disso explicitamente.
        'customtkinter',
        'PIL._tkinter_finder',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='DevSec',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Adicione um .ico em assets/logos/ e aponte aqui, ex: icon='assets/logos/devsec.ico'
    icon=None,
    # Faz o Windows pedir elevação (UAC) automaticamente ao abrir o programa,
    # necessário para captura real de pacotes e regras de firewall.
    uac_admin=True,
)
