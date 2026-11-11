$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (Get-Command pipx -ErrorAction SilentlyContinue) {
    pipx install --force $RootDir
    Write-Host "Installed n8n-lint via pipx."
    exit 0
}

if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv tool install --force $RootDir
    Write-Host "Installed n8n-lint via uv."
    exit 0
}

$env:PYTHONPATH = Join-Path $RootDir "src"
python -m n8n_lint --version
Write-Host "Run via: python -m n8n_lint scan examples/clean_workflow.json"
