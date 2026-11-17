#!/usr/bin/env bash
# Linux/macOS launcher. Live capture needs root on Linux:  sudo ./run.sh
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt 2>/dev/null || python3 -m pip install -q Flask reportlab
exec python3 app.py "$@"
