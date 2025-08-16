Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
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