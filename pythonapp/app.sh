echo "Creating python environment..."

# Set up environment
export VIRTUAL_ENV=/data/venv
python -m pip install uv --root-user-action ignore
cd /app
uv venv --allow-existing ${VIRTUAL_ENV}
source ${VIRTUAL_ENV}/bin/activate

echo "=== RUNNING SCRIPT V2 ==="

# Tell uv to use a writable directory for its cache and temp files
export UV_CACHE_DIR=/data/uv-cache
uv sync --active --frozen

echo "Starting app..."
python fastapi-authlib.py
#python flask-authlib.py