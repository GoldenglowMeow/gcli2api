#!/bin/bash

if [ "$(whoami)" = "root" ]; then
    echo "检测到root用户，正在退出..."
    exit
fi

echo "正在设置Termux镜像为Cloudflare镜像..."

# 备份原始sources.list文件
if [ -f "$PREFIX/etc/apt/sources.list" ]; then
    echo "备份原始sources.list文件..."
    cp "$PREFIX/etc/apt/sources.list" "$PREFIX/etc/apt/sources.list.backup.$(date +%Y%m%d_%H%M%S)"
fi

# 写入新的镜像源
echo "写入新的镜像源配置..."
cat > "$PREFIX/etc/apt/sources.list" << 'EOF'
# Cloudflare镜像源
deb https://packages-cf.termux.dev/apt/termux-main stable main
EOF

echo "镜像源已更新为: https://packages-cf.termux.dev/apt/termux-main"

# 更新包列表
echo "正在更新包列表..."
apt update

echo "✅ Termux镜像设置完成！"
echo "📁 原始配置已备份到: $PREFIX/etc/apt/sources.list.backup.*"
echo "🔄 如需恢复原始镜像，可以运行:"
echo "   cp \$PREFIX/etc/apt/sources.list.backup.* \$PREFIX/etc/apt/sources.list && apt update"

# 检查是否需要更新包管理器和安装软件
need_update=false
packages_to_install=""

# 检查 uv 是否已安装
if ! command -v uv &> /dev/null; then
    need_update=true
    packages_to_install="$packages_to_install uv"
fi

# 检查 python 是否已安装
if ! command -v python &> /dev/null; then
    need_update=true
    packages_to_install="$packages_to_install python"
fi

# 检查 nodejs 是否已安装
if ! command -v node &> /dev/null; then
    need_update=true
    packages_to_install="$packages_to_install nodejs"
fi

# 检查 git 是否已安装
if ! command -v git &> /dev/null; then
    need_update=true
    packages_to_install="$packages_to_install git"
fi

# 如果需要安装软件，则更新包管理器并安装
if [ "$need_update" = true ]; then
    echo "正在更新包管理器..."
    pkg update && pkg upgrade -y
    echo "正在安装缺失的软件包:$packages_to_install"
    pkg install$packages_to_install -y
else
    echo "所需软件包已全部安装，跳过更新和安装步骤"
fi

# 检查 pm2 是否已安装
if ! command -v pm2 &> /dev/null; then
    echo "正在安装 pm2..."
    npm install pm2 -g
else
    echo "pm2 已安装，跳过安装"
fi

# 项目目录处理逻辑
if [ -f "./web.py" ]; then
    # Already in target directory; skip clone and cd
    echo "已在目标目录中，跳过克隆操作"
elif [ -f "./gcli2api/web.py" ]; then
    echo "进入已存在的 gcli2api 目录"
    cd ./gcli2api
else
    echo "克隆项目仓库..."
    git clone https://github.com/su-kaka/gcli2api.git
    cd ./gcli2api
fi

echo "更新项目代码..."
git pull

echo "初始化 uv 环境..."
uv init

echo "安装 Python 依赖..."
uv add -r requirements-termux.txt

echo "激活虚拟环境并启动服务..."
source .venv/bin/activate
pm2 start .venv/bin/python --name web -- web.py
cd ..