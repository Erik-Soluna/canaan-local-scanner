FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Python package layout for `uvicorn canaan_scanner.app.main:app`
COPY __init__.py /app/canaan_scanner/__init__.py
COPY app /app/canaan_scanner/app

# Record the git revision baked into this image (override at build: --build-arg GIT_SHA=$(git rev-parse HEAD))
ARG GIT_SHA=unknown
ENV GIT_SHA=${GIT_SHA}
# File fallback: same directory as main.py (see get_deploy_sha in app/update_check.py)
RUN if [ -n "${GIT_SHA}" ] && [ "${GIT_SHA}" != "unknown" ]; then printf '%s' "${GIT_SHA}" > /app/canaan_scanner/app/.deploy_sha; fi

EXPOSE 8000

CMD ["uvicorn", "canaan_scanner.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
