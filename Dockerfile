FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY default_node.py verify_record.py ./
ENV DEFAULT_DB=/data/default_ledger.db \
    DEFAULT_KEY_PATH=/data/default_node_key.pem
VOLUME /data
EXPOSE 8080
CMD ["python3", "default_node.py"]
