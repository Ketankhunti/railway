FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
LABEL rail.project="proj_demo"
LABEL rail.service="api-gateway"
LABEL rail.env="production"
EXPOSE 8001
CMD ["python", "app.py"]
