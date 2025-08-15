pkg install rust build-essential python git ninja clang cmake uv npm
npm install pm2 -g
git clone https://github.com/su-kaka/gcli2api.git
cd ./gcli2api
uv sync
source .venv/Scripts/activate
pm2 start python web.py