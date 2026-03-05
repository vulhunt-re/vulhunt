# VulHunt CE Installer for Windows
# Usage: irm https://raw.githubusercontent.com/binarly-io/vulhunt-ce/dev/scripts/install.ps1 | iex

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

$Repo = "binarly-io/vulhunt-ce"
$DataUrl = "https://github.com/binarly-io/binarly-static-data/archive/refs/heads/platform-v2.0.zip"
$InstallDir = if ($env:VULHUNT_INSTALL_DIR) { $env:VULHUNT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "vulhunt-ce" }
$BinDir = if ($env:VULHUNT_BIN_DIR) { $env:VULHUNT_BIN_DIR } else { Join-Path $InstallDir "bin" }
$DataDir = Join-Path $env:LOCALAPPDATA "vulhunt\data"

function Write-Info {
    param([string]$Message)
    Write-Host "info: " -ForegroundColor Blue -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "warn: " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Err {
    param([string]$Message)
    Write-Host "error: " -ForegroundColor Red -NoNewline
    Write-Host $Message
    exit 1
}

function Write-Success {
    param([string]$Message)
    Write-Host "success: " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Get-Architecture {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64" { return "x86_64" }
        "Arm64" { return "aarch64" }
        default { Write-Err "Unsupported architecture: $arch" }
    }
}

function Get-LatestRelease {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        return $response.tag_name
    }
    catch {
        Write-Err "Failed to fetch latest release: $_"
    }
}

function Get-DownloadUrl {
    param(
        [string]$Version,
        [string]$Platform
    )
    $verStripped = $Version -replace '^v', ''  # Strip 'v' prefix if present
    return "https://github.com/$Repo/releases/download/$Version/vulhunt-ce-$verStripped-$Platform.zip"
}

function Install-StaticData {
    param([string]$TempDir)

    Write-Info "Downloading auxiliary data..."
    $dataZipPath = Join-Path $TempDir "data.zip"
    $dataExtractPath = Join-Path $TempDir "data_extracted"

    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $DataUrl -OutFile $dataZipPath -UseBasicParsing
    $ProgressPreference = 'Continue'

    Write-Info "Extracting auxiliary data to $DataDir..."
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Expand-Archive -Path $dataZipPath -DestinationPath $dataExtractPath -Force

    $extractedFolder = Get-ChildItem -Path $dataExtractPath -Directory | Select-Object -First 1
    $dataFolder = Join-Path $extractedFolder.FullName "data"
    Get-ChildItem -Path $dataFolder | Move-Item -Destination $DataDir -Force
}

function Install-VulHuntCE {
    Write-Info "Detecting system..."

    $arch = Get-Architecture
    $platform = "windows-$arch"

    Write-Info "Detected platform: $platform"

    Write-Info "Fetching latest release..."
    $version = if ($env:VULHUNT_VERSION) { $env:VULHUNT_VERSION } else { Get-LatestRelease }

    if (-not $version) {
        Write-Err "Failed to determine latest version. Set VULHUNT_VERSION to install a specific version."
    }

    Write-Info "Installing VulHunt CE $version..."

    $downloadUrl = Get-DownloadUrl -Version $version -Platform $platform
    Write-Info "Downloading from: $downloadUrl"

    $tempDir = Join-Path $env:TEMP "vulhunt-ce-install-$(Get-Random)"
    $zipPath = Join-Path $tempDir "vulhunt-ce.zip"
    $extractPath = Join-Path $tempDir "extracted"

    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        $ProgressPreference = 'Continue'

        Write-Info "Extracting..."

        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null

        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        $binaries = @("vulhunt-ce.exe", "bias-lutil.exe", "bias-tutil.exe", "sleighc.exe")
        foreach ($binary in $binaries) {
            $sourcePath = Join-Path $extractPath $binary
            if (Test-Path $sourcePath) {
                $destPath = Join-Path $BinDir $binary
                Move-Item -Path $sourcePath -Destination $destPath -Force
            }
        }

        Set-Content -Path (Join-Path $InstallDir "version") -Value $version

        Install-StaticData -TempDir $tempDir

        Write-Success "VulHunt CE $version installed to $BinDir"

        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$BinDir*") {
            Write-Host ""
            Write-Warn "VulHunt CE is not in your PATH."
            Write-Host ""
            Write-Host "To add it to your PATH, run the following command:" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  `$env:Path += `";$BinDir`"" -ForegroundColor White
            Write-Host "  [Environment]::SetEnvironmentVariable('Path', `$env:Path + ';$BinDir', 'User')" -ForegroundColor White
            Write-Host ""

            $addToPath = Read-Host "Would you like to add VulHunt CE to your PATH now? [Y/n]"
            if ($addToPath -eq "" -or $addToPath -ieq "y" -or $addToPath -ieq "yes") {
                $newPath = $userPath + ";" + $BinDir
                [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
                $env:Path = $env:Path + ";" + $BinDir
                Write-Success "Added to PATH. You may need to restart your terminal."
            }
        }

        $biasDataEnv = [Environment]::GetEnvironmentVariable("BIAS_DATA", "User")
        if (-not $biasDataEnv) {
            Write-Host ""
            Write-Warn "BIAS_DATA environment variable is not set."
            Write-Host ""
            Write-Host "To set it, run the following command:" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  [Environment]::SetEnvironmentVariable('BIAS_DATA', '$DataDir', 'User')" -ForegroundColor White
            Write-Host ""

            $setBiasData = Read-Host "Would you like to set BIAS_DATA now? [Y/n]"
            if ($setBiasData -eq "" -or $setBiasData -ieq "y" -or $setBiasData -ieq "yes") {
                [Environment]::SetEnvironmentVariable("BIAS_DATA", $DataDir, "User")
                $env:BIAS_DATA = $DataDir
                Write-Success "BIAS_DATA set. You may need to restart your terminal."
            }
        }

        Write-Host ""
        Write-Success "Installation complete!"
        Write-Host ""
        Write-Info "Run 'vulhunt-ce --help' to get started"
    }
    catch {
        Write-Err "Installation failed: $_"
    }
    finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Install-VulHuntCE
