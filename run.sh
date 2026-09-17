#!/data/data/com.termux/files/usr/bin/bash
# Hospital AI Security (v3) - Termux launcher
# Usage: ./run.sh  (then open http://127.0.0.1:8002)
cd "$(dirname "$0")"
if [ ! -d "venv" ]; then
  echo "venv missing - creating with system site packages (for numpy)..."
  python3 -m venv --system-site-packages venv
  ./venv/bin/pip install --prefer-binary -r requirements-termux.txt
fi
if [ ! -f "instance/hospital_security.db" ]; then
  echo "WARNING: instance/hospital_security.db missing!"
  echo "Restore from backup or run: ./venv/bin/python seed_db.py  (needs scikit-learn/pandas on PC)"
fi
echo "Starting on http://127.0.0.1:8002 ..."
exec ./venv/bin/python app.py
