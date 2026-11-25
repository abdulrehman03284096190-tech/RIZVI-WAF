$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    $venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $venvPython)) {
        python -m venv .venv
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create the local build environment."
        }
    }

    & $venvPython -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        throw "Could not install the build requirements."
    }

    & $venvPython installer\generate_branding.py
    if ($LASTEXITCODE -ne 0) {
        throw "Could not generate the installer branding assets."
    }

    $appIcon = Join-Path $projectRoot "installer\RIZVI-WAF.ico"
    $versionInfo = Join-Path $projectRoot "installer\version_info.txt"
    $entryPoint = Join-Path $projectRoot "app.py"
    & $venvPython -m PyInstaller `
        --clean `
        --noconfirm `
        --windowed `
        --onedir `
        --name "RIZVI WAF" `
        --icon $appIcon `
        --version-file $versionInfo `
        --distpath dist `
        --specpath build\pyinstaller `
        --workpath build\pyinstaller `
        $entryPoint
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed to build the desktop application."
    }

    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
    if (-not $iscc) {
        $innoCandidates = @(
            (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
            (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
            (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe")
        )
        $iscc = $innoCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $iscc) {
        throw "Inno Setup 6 is required. Install it with: winget install --id JRSoftware.InnoSetup --exact"
    }

    & $iscc installer\RIZVI-WAF.iss
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup failed to create the installer."
    }

    Write-Output "Installer created: dist\installer\RIZVI-WAF-Setup-1.0.0.exe"
}
finally {
    Pop-Location
}
