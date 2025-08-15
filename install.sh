apt update && apt upgrade -y
apt install git
curl -Ls https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env.sh
git clone https://github.com/su-kaka/gcli2api.git
cd ./gcli2api
git pull
uv sync
source .venv/bin/activate
python3 web.py