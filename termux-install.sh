pkg update && pkg upgrade -y
pkg install python git uv nodejs -y
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
uv init
uv add -r requirements-termux.txt
source .venv/bin/activate
pm2 start .venv/bin/python --name web -- web.py