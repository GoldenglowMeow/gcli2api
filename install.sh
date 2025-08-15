pkg update && pkg upgrade -y
apt install git uv pm2
git clone https://github.com/su-kaka/gcli2api.git
cd ./gcli2api
uv sync
source .venv/Scripts/activate
pm2 start python web.py