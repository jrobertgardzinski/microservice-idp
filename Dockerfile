# Stub OIDC provider — Python stdlib only, no dependencies. Lets the stack demo social login
# without a real Google client; microservice-security's OAuth adapter only changes URLs.
FROM python:3.12-slim
WORKDIR /app
COPY server.py .
EXPOSE 8090
CMD ["python", "server.py"]
