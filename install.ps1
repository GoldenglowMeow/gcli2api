# 检测是否为管理员
$IsElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Add-ScoopShimsToPath {
    $candidates = @(
        (Join-Path $env:USERPROFILE 'scoop\shims'),
        (Join-Path $env:ProgramData 'scoop\shims')
    )
    foreach ($p in $candidates) {
        if (Test-Path $p -and -not (($env:PATH -split ';') -contains $p)) {
            $env:PATH = "$p;$env:PATH"
        }
    }
}

# Skip Scoop install if already present to avoid stopping the script
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Host "Scoop is already installed. Skipping installation."
    Add-ScoopShimsToPath
} else {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    if ($IsElevated) {
        # 管理员：使用官方一行命令并传入 -RunAsAdmin
        iex "& {$(irm get.scoop.sh)} -RunAsAdmin"
    } else {
        # 普通用户安装
        iwr -useb get.scoop.sh | iex
    }
    # 确保当前会话能找到 scoop
    Add-ScoopShimsToPath
}

scoop install git uv
if (Test-Path -LiteralPath "./web.py") {
    # Already in target directory; skip clone and cd
}
elseif (Test-Path -LiteralPath "./gcli2api/web.py") {
    Set-Location ./gcli2api
}
else {
    git clone https://github.com/su-kaka/gcli2api.git
    Set-Location ./gcli2api
}
uv sync
.venv/Scripts/activate.ps1
python web.py