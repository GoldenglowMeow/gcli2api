pkg update && pkg upgrade -y
pkg install rust build-essential python git ninja clang cmake uv nodejs binutils-is-llvm binutils -y
npm install pm2 -g
if [ -f "./web.py" ]; then
    # Already in target directory; skip clone and cd
    :
elif [ -f "./gcli2api/web.py" ]; then
    cd ./gcli2api
else
    git clone https://github.com/su-kaka/gcli2api.git
    cd ./gcli2api
fi
git pull
uv sync
source .venv/bin/activate
pm2 start python3 web.py