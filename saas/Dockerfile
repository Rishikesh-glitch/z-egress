FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir flask zstandard gunicorn
COPY app.py .
COPY templates/ templates/
EXPOSE 8080
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8080", "--timeout", "120", "app:app"]
