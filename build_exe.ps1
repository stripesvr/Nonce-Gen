<#
    build_exe.ps1 — rebuild QuestAttest.exe and drop it in Downloads.

    PyInstaller chokes on relative --specpath and on mkdir inside some synced
    workspaces, so the build runs from a temp staging folder with absolute paths.

    Icon source: any square PNG. It gets wrapped as a PNG-payload .ico (Vista+)
    and baked into the exe plus bundled as a window icon.
#>

param(
    [string]$IconPng = "C:\Users\VirtualStripes\Downloads\Proycontec-Robots-Robot-documents.256.png"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$stage = Join-Path $env:TEMP "opencode\qbuild"
$spec = Join-Path $stage "pyspec"
$work = Join-Path $stage "work"
$out = Join-Path $env:USERPROFILE "Downloads"
$ico = Join-Path $stage "icon.ico"

New-Item -ItemType Directory -Force -Path $stage, $spec | Out-Null
Copy-Item (Join-Path $root "gui.py") (Join-Path $root "meta_attest.py") -Destination $stage -Force

$env:ICON_PNG = $IconPng
$env:ICON_ICO = $ico
python -c "import os, struct; png=open(os.environ['ICON_PNG'],'rb').read(); hdr=struct.pack('<HHH',0,1,1); ent=struct.pack('<BBBBHHII',0,0,0,0,1,32,len(png),22); open(os.environ['ICON_ICO'],'wb').write(hdr+ent+png)"

pyinstaller `
    --noconfirm --onefile --windowed `
    --name QuestAttest `
    --icon $ico `
    --add-data "$ico;." `
    --distpath $stage `
    --workpath $work `
    --specpath $spec `
    (Join-Path $stage "gui.py")

Copy-Item (Join-Path $stage "QuestAttest.exe") (Join-Path $out "QuestAttest.exe") -Force
Get-Item (Join-Path $out "QuestAttest.exe") | Format-List FullName, Length, LastWriteTime
