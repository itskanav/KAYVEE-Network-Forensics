@echo off
cd /d "%~dp0"
python -m pip install -q Flask reportlab maxminddb
python app.py %*
