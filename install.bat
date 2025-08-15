@echo off
setlocal

rem Install Scoop if missing
set "SCOOP_SHIMS=%USERPROFILE%\scoop\shims"
if not exist "%SCOOP_SHIMS%\scoop.cmd" (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb get.scoop.sh | iex"
)

rem Resolve tools from Scoop shims if available
if exist "%SCOOP_SHIMS%\scoop.cmd" (set "SCOOP=%SCOOP_SHIMS%\scoop.cmd") else (set "SCOOP=scoop")
if exist "%SCOOP_SHIMS%\git.exe" (set "GIT=%SCOOP_SHIMS%\git.exe") else (set "GIT=git")
if exist "%SCOOP_SHIMS%\uv.exe" (set "UV=%SCOOP_SHIMS%\uv.exe") else (set "UV=uv")

%SCOOP% install uv git
%GIT% clone https://github.com/su-kaka/gcli2api.git
cd /d gcli2api
%UV% sync
call venv\Scripts\activate.bat
python web.py
