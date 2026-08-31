FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iptables iproute2 procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "mitmproxy==11.*"

COPY addons/ /addons/
COPY entrypoint.sh /usr/local/bin/lab-proxy-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-proxy-entrypoint.sh

EXPOSE 8080 8081 8082
ENTRYPOINT ["/usr/local/bin/lab-proxy-entrypoint.sh"]
