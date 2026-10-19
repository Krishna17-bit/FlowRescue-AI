FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY flowrescue ./flowrescue
COPY examples ./examples
EXPOSE 8080
USER 1000
CMD ["uvicorn","flowrescue.web:app","--host","0.0.0.0","--port","8080"]
