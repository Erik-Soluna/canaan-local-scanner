FROM python:3.12-slim

WORKDIR /app

COPY canaan_scanner/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY canaan_scanner /app/canaan_scanner

EXPOSE 8000

CMD ["uvicorn", "canaan_scanner.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

