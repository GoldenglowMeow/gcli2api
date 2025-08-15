pkg update && pkg upgrade -y
pkg install rust build-essential python git ninja clang cmake uv nodejs -y
npm install pm2 -g
git clone https://github.com/su-kaka/gcli2api.git
cd ./gcli2api
uv sync
source .venv/bin/activate
pm2 start python3 web.py