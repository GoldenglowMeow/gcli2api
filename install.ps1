# Skip Scoop install if already present to avoid stopping the script
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Host "Scoop is already installed. Skipping installation."
} else {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
    # Ensure current session can find scoop
    if (-not (Get-Command scoop -ErrorAction SilentlyContinue)) {
        $scoopShims = Join-Path $env:USERPROFILE 'scoop\shims'
        if (Test-Path $scoopShims) { $env:PATH = "$scoopShims;$env:PATH" }
    }
}
scoop install git uv
if (Test-Path -LiteralPath "./web.py") {
    # Already in target directory; skip clone and cd
}
elseif (Test-Path -LiteralPath "./gcli2api/web.py") {
    Set-Location ./gcli2api
}
else {
    git clone https://github.com/su-kaka/gcli2api.git
    Set-Location ./gcli2api
}
uv sync
.venv/Scripts/activate.ps1
python web.py