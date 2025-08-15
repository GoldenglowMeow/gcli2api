pkg install rust build-essential python git ninja clang cmake uv
git clone https://github.com/su-kaka/gcli2api.git
cd ./gcli2api
uv sync
source ./venv/Scripts/activate
python web.py