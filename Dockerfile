FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VIRTUALENVS_CREATE=false VPNFORGE_DATA_DIR=/app/data VPNFORGE_PUBLIC_DEMO=true \
    ANSIBLE_HOME=/tmp/ansible
WORKDIR /app
RUN pip install --no-cache-dir poetry==2.2.1
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --only main,demo --no-root --no-interaction --no-ansi
COPY vpnforge ./vpnforge
COPY ansible/demo ./ansible/demo
RUN useradd --uid 10001 --create-home bypass && mkdir /app/data && chown bypass /app/data
USER bypass
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s \
 CMD python -c "import os, urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/health', headers={'Host': os.environ.get('VPNFORGE_PUBLIC_HOST', 'localhost')}), timeout=3)"
CMD ["uvicorn", "vpnforge.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
