# Stub OIDC provider — Python stdlib only, no dependencies. Lets the stack demo social login
# without a real Google client; microservice-security's OAuth adapter only changes URLs.
FROM python:3.12-slim
WORKDIR /app
COPY server.py .
# Drop root, like the image encoder this service is modelled on. The divergence was an
# oversight, not a decision — and this is the layer the header-injection fix above lives in.
RUN useradd --system --no-create-home idp
USER idp
EXPOSE 8090
CMD ["python", "server.py"]
