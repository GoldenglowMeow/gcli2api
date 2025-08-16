git pull
uv sync
source .venv/bin/activate
pm2 start .venv/bin/python --name web -- web.py