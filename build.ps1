param([ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')][string]$Version)
$ErrorActionPreference = 'Stop'
$projectPath = $PSScriptRoot
$pythonPath = Join-Path $projectPath '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = Join-Path (Split-Path $projectPath -Parent) '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $pythonPath)) { $pythonPath = 'python' }
Set-Location -LiteralPath $projectPath
$sourceVersion = (& $pythonPath -c 'from deployer import __version__; print("v" + __version__)').Trim()
if ($LASTEXITCODE -ne 0 -or $sourceVersion -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Cannot read the application version' }
if ($Version -and $Version -ne $sourceVersion) { throw 'Build version must match deployer/__init__.py' }
$Version = $sourceVersion
$distPath = Join-Path $projectPath 'dist'
$distPath = Join-Path $distPath $Version
$buildOutput = [System.IO.Path]::GetFullPath((Join-Path $distPath 'NodePilot'))
if (-not $buildOutput.StartsWith($projectPath + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Build output is outside the project' }
if ((Test-Path -LiteralPath $buildOutput) -and ((Get-Item -LiteralPath $buildOutput).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'Build output must not be a linked directory' }
$env:PYINSTALLER_CONFIG_DIR = Join-Path $projectPath '.pyinstaller-cache'
if (-not (Test-Path -LiteralPath (Join-Path $projectPath 'assets\core\xray.exe'))) {
    & $pythonPath -u tools/fetch_core.py
    if ($LASTEXITCODE -ne 0) { throw 'Official test core download failed' }
}
& $pythonPath tools/collect_licenses.py
if ($LASTEXITCODE -ne 0) { throw 'License collection failed' }
$previousBuildPath = $env:PATH
try {
    # Avoid collecting unrelated DLLs from the host's PDF/image tool runtimes.
    $env:PATH = "$(Split-Path $pythonPath -Parent);$env:WINDIR\System32;$env:WINDIR"
    & $pythonPath -m PyInstaller --clean --noconfirm --windowed --onedir --distpath $distPath --name NodePilot --icon 'assets/branding/nodepilot.ico' --add-data 'assets;assets' --collect-all qrcode --hidden-import PIL.ImageQt main.py
} finally { $env:PATH = $previousBuildPath }
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
Copy-Item -LiteralPath (Join-Path $projectPath 'docs\user-guide.md') -Destination (Join-Path $buildOutput '使用说明.md')
Copy-Item -LiteralPath (Join-Path $projectPath 'THIRD_PARTY_NOTICES.md') -Destination (Join-Path $buildOutput 'THIRD_PARTY_NOTICES.md')
Compress-Archive -LiteralPath $buildOutput -DestinationPath (Join-Path $projectPath ('dist\NodePilot-'+$Version+'-Windows-x64.zip')) -Force
& $pythonPath tools/package_source.py
if ($LASTEXITCODE -ne 0) { throw 'Source archive creation failed' }
Write-Output 'Portable Windows app created'
