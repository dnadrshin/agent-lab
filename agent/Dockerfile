FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq less procps python3 ripgrep \
      iproute2 iptables dnsutils openssh-client gosu nano \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code \
 && npm cache clean --force

RUN useradd -m -u 1001 -s /bin/bash agent

COPY hooks/ /opt/agent-lab/hooks/
COPY settings.json /opt/agent-lab/settings.json
COPY entrypoint.sh /usr/local/bin/lab-agent-entrypoint.sh
RUN chmod +x /usr/local/bin/lab-agent-entrypoint.sh /opt/agent-lab/hooks/*.py

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/lab-agent-entrypoint.sh"]
CMD ["bash", "-l"]
