Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
scoop install git uv
git clone https://github.com/su-kaka/gcli2api.git
Set-Location ./gcli2api
uv sync
.venv/Scripts/activate.ps1
python web.py