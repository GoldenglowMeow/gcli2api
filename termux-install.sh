#!/data/data/com.termux/files/usr/bin/bash
is_root=false
if [ "$(id -u)" -eq 0 ]; then
  is_root=true
fi

# 在 root 情况下，将命令改为以 Termux 普通用户身份执行
as_termux_user() {
  # 通过 PREFIX 目录的属主，获取 Termux 应用用户的 uid/gid（兼容 toybox）
  local prefix="${PREFIX:-/data/data/com.termux/files/usr}"
  local home="${HOME:-/data/data/com.termux/files/home}"
  local uid gid
  uid=$(ls -nd "$prefix" | awk '{print $3}')
  gid=$(ls -nd "$prefix" | awk '{print $4}')
  local cmd="$*"

  if command -v su >/dev/null 2>&1 && su -h 2>&1 | grep -q -- "-u"; then
    su -u "$uid" -g "$gid" -c "export HOME='$home'; export PREFIX='$prefix'; export PATH='$prefix/bin:$home/.local/bin:\$PATH'; bash -lc \"$cmd\""
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "#$uid" -- bash -lc "export HOME='$home'; export PREFIX='$prefix'; export PATH='$prefix/bin:$home/.local/bin:\$PATH'; $cmd"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u "#$uid" bash -lc "export HOME='$home'; export PREFIX='$prefix'; export PATH='$prefix/bin:$home/.local/bin:\$PATH'; $cmd"
  else
    echo "无法以 Termux 普通用户身份执行命令，请退出 root 后重试。"
    exit 1
  fi
}

run() {
  if $is_root; then
    as_termux_user "$*"
  else
    bash -lc "$*"
  fi
}

# ---------------- 安装与部署 ----------------
run "pkg update -y && pkg upgrade -y"

# python/git/nodejs 基础依赖
run "pkg install -y python git nodejs"

# uv：优先用包管理器；没有则用官方安装脚本
run '
  (pkg install -y uv 2>/dev/null || true);
  if ! command -v uv >/dev/null 2>&1; then
    echo \"安装 uv（官方脚本）...\";
    curl -LsSf https://astral.sh/uv/install.sh | sh
  fi
  export PATH=\"$HOME/.local/bin:\$PATH\"
  grep -q \"HOME/.local/bin\" \"$HOME/.bashrc\" 2>/dev/null || echo \"export PATH=\\\"$HOME/.local/bin:\\\$PATH\\\"\" >> \"$HOME/.bashrc\"
'

# pm2
run "npm install -g pm2"

# 代码获取与依赖安装（在用户家目录操作，避免 root 写入）
run '
    # 直接在当前目录操作
    proj_dir="$PWD"
    cd "$proj_dir" || exit 1

    # 使用 uv 虚拟环境并安装依赖
    uv venv
    source .venv/bin/activate
    if [ -f requirements-termux.txt ]; then
        uv pip install -r requirements-termux.txt
    elif [ -f requirements.txt ]; then
        uv pip install -r requirements.txt
    fi

    # 用 pm2 启动
    pm2 start .venv/bin/python --name web -- web.py
    pm2 save
'

echo "完成：服务已通过 pm2 启动。使用 'pm2 status' 查看状态。"