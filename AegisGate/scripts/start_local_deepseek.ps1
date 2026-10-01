param(
    [string]$Python,
    [string]$RuntimeDirectory,
    [int]$Port = 8765,
    [switch]$NoBrowser,
    [switch]$SetupOnly
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$LocalRoot = Join-Path $ProjectRoot 'runtime/local-deepseek'
$OllamaRoot = Join-Path $LocalRoot 'ollama'
$Ollama = Join-Path $OllamaRoot 'ollama.exe'
$Logs = Join-Path $LocalRoot 'logs'
$SettingsPath = Join-Path $LocalRoot 'launch-settings.json'
$Model = 'aegis-deepseek-v2:16b'
$BaseModel = 'deepseek-v2:16b'
$ModelConfig = Join-Path $ProjectRoot 'config/deepseek_local.json'
$Utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $OllamaRoot, $Logs, (Join-Path $LocalRoot 'models'), (Join-Path $LocalRoot 'downloads') | Out-Null

if (-not (Test-Path -LiteralPath $Ollama)) {
    $Archive = Join-Path $LocalRoot 'downloads/ollama-windows-amd64.zip'
    $ExpectedHash = '8F3FD071A2A2F9497B562F43502C77C2B701A99D1EE5DFDA28DA8C786373063B'
    $ArchiveValid = (Test-Path -LiteralPath $Archive) -and ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -eq $ExpectedHash)
    if (-not $ArchiveValid) {
        Write-Host 'Downloading official Ollama v0.34.2 (1.46 GB)...'
        & curl.exe --location --fail --retry 4 --output $Archive 'https://github.com/ollama/ollama/releases/download/v0.34.2/ollama-windows-amd64.zip'
        if ($LASTEXITCODE -ne 0) { throw 'Ollama download failed. Run this launcher again to retry.' }
    }
    if ((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -ne $ExpectedHash) { throw 'Ollama archive SHA256 mismatch.' }
    & tar.exe -xf $Archive -C $OllamaRoot
    if ($LASTEXITCODE -ne 0) { throw 'Ollama extraction failed.' }
}

$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_MODELS = Join-Path $LocalRoot 'models'
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_CONTEXT_LENGTH = '4096'
$env:OLLAMA_KEEP_ALIVE = '10m'
# Local inference must not inherit a cloud credential.
Remove-Item Env:DEEPSEEK_API_KEY -ErrorAction SilentlyContinue

function Get-OllamaVersion {
    try { return Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version' -TimeoutSec 3 }
    catch { return $null }
}

if (-not (Get-OllamaVersion)) {
    $OllamaProcess = Start-Process -FilePath $Ollama -ArgumentList 'serve' -WorkingDirectory $OllamaRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Logs 'ollama.out.log') -RedirectStandardError (Join-Path $Logs 'ollama.err.log')
    [System.IO.File]::WriteAllText((Join-Path $LocalRoot 'ollama.pid'), [string]$OllamaProcess.Id, $Utf8)
    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
        if (Get-OllamaVersion) { $Ready = $true; break }
        if ($OllamaProcess.HasExited) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $Ready) { throw "Ollama did not start. See $Logs" }
}

$Models = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 10
if ($BaseModel -notin $Models.models.name) {
    Write-Host 'Downloading DeepSeek-V2-Lite Chat 16B Q4_0 (8.91 GB)...'
    & $Ollama pull $BaseModel
    if ($LASTEXITCODE -ne 0) { throw 'Model download failed. Run this launcher again to resume.' }
}
& $Ollama create $Model -f (Join-Path $ProjectRoot 'config/DeepSeekV2.Modelfile')
if ($LASTEXITCODE -ne 0) { throw 'Local model profile creation failed.' }
if ($SetupOnly) { Write-Host "Model ready: $Model"; exit 0 }

$Saved = $null
if (Test-Path -LiteralPath $SettingsPath) { $Saved = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 | ConvertFrom-Json }
if (-not $Python -and $Saved) { $Python = $Saved.python }
if (-not $Python) {
    $Candidates = @((Join-Path $ProjectRoot '.venv/Scripts/python.exe'))
    $Python = $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $Python) { $Python = (Get-Command python -ErrorAction Stop).Source }
}
& $Python -c 'import numpy, onnxruntime' 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Python runtime dependencies are missing. Install requirements.txt with the selected Python.' }
if (-not $RuntimeDirectory -and $Saved) { $RuntimeDirectory = $Saved.runtime_dir }
if (-not $RuntimeDirectory) { $RuntimeDirectory = Join-Path $ProjectRoot 'runtime' }
if (-not [System.IO.Path]::IsPathRooted($RuntimeDirectory)) { $RuntimeDirectory = Join-Path $ProjectRoot $RuntimeDirectory }

$Address = "http://127.0.0.1:$Port"
$Headers = @{}
if ($env:AEGIS_API_TOKEN) { $Headers.Authorization = "Bearer $($env:AEGIS_API_TOKEN)" }
$Existing = $null
try { $Existing = Invoke-RestMethod -Uri "$Address/api/v1/model/status" -Headers $Headers -TimeoutSec 3 } catch {}
if ($Existing -and $Existing.model_name -ne $Model) {
    throw "Port $Port is running another model configuration. Stop that AegisGate instance first, or use -Port with a free port."
}
if (-not $Existing) {
    $Arguments = @('-u', ('"' + (Join-Path $ProjectRoot 'scripts/launch_demo.py') + '"'), '--host', '127.0.0.1', '--port', $Port, '--no-browser', '--model-config', ('"' + $ModelConfig + '"'), '--runtime-dir', ('"' + $RuntimeDirectory + '"'))
    $GatewayProcess = Start-Process -FilePath $Python -ArgumentList $Arguments -WorkingDirectory $ProjectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Logs 'gateway.out.log') -RedirectStandardError (Join-Path $Logs 'gateway.err.log')
    [System.IO.File]::WriteAllText((Join-Path $LocalRoot 'gateway.pid'), [string]$GatewayProcess.Id, $Utf8)
    $Ready = $false
    for ($Attempt = 0; $Attempt -lt 45; $Attempt++) {
        try {
            $Status = Invoke-RestMethod -Uri "$Address/api/v1/model/status" -Headers $Headers -TimeoutSec 3
            if ($Status.model_name -eq $Model) { $Ready = $true; break }
        } catch {}
        if ($GatewayProcess.HasExited) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $Ready) { throw "AegisGate did not start on $Address. See $Logs" }
}
$Settings = @{ python = $Python; runtime_dir = $RuntimeDirectory; port = $Port; model = $Model }
[System.IO.File]::WriteAllText($SettingsPath, ($Settings | ConvertTo-Json), $Utf8)
Write-Host "AegisGate: $Address/?view=detect"
Write-Host "Local model: $Model (DeepSeek-V2-Lite Chat, 16B Q4_0)"
if (-not $NoBrowser) { Start-Process "$Address/?view=detect" }
