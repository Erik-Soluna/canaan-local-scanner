FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

ARG GIT_SHA=unknown
COPY app /app/app
RUN echo -n "${GIT_SHA}" > /app/app/.deploy_sha

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]