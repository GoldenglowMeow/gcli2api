git pull
uv add -r requirements-termux.txt
source .venv/bin/activate
pm2 start .venv/bin/python --name web -- web.py