pkg install rust build-essential python git ninja clang cmake
git clone https://github.com/su-kaka/gcli2api.git
cd ./gcli2api
pip install -r requirements.txt --break-system-packages
python web.py