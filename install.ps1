$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv = Join-Path $ProjectRoot '.venv'
py -3 -m venv $Venv
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required to create the virtual environment.' }
& (Join-Path $Venv 'Scripts\python.exe') -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'Could not upgrade pip.' }
& (Join-Path $Venv 'Scripts\python.exe') -m pip install $ProjectRoot
if ($LASTEXITCODE -ne 0) { throw 'Could not install SecQuery dependencies.' }
& (Join-Path $Venv 'Scripts\python.exe') -m pip install 'yara-python>=4.5'
if ($LASTEXITCODE -ne 0) { Write-Warning 'Optional YARA install failed; built-in checks and other engines remain available.' }
Write-Host 'Installed. Run .\.venv\Scripts\secquery.exe --help'
