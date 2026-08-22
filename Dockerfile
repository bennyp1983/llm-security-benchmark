# Run for detailed build sudo docker build --no-cache --progress=plain -t n8n-benchmark .
# Run for clean rebuild: docker compose build --no-cache

# Pin n8n version to current latest version. (npm-based installs are deprecated from n8n 3.0)
# https://docs.n8n.io/deploy/host-n8n/install-options/install-with-npm
ARG N8N_VERSION=2.36

FROM node:24.19.0-bookworm-slim

RUN apt-get update && apt-get install -y curl bash git && rm -rf /var/lib/apt/lists/*

RUN npm install -g n8n@${N8N_VERSION}

# Install Claude CLI
# https://code.claude.com/docs/en/terminal-guide#macos-and-linux
RUN curl -fsSL https://claude.ai/install.sh | bash

# Install ChatGPT Codex CLI
# https://learn.chatgpt.com/docs/codex/cli
RUN curl -fsSL https://chatgpt.com/codex/install.sh | sh

# Install Antigravity CLI
# https://antigravity.google/docs/cli/install
RUN curl -fsSL https://antigravity.google/cli/install.sh | bash

# Install Qwen CLI
# https://qwen.ai/qwencode
RUN curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash

# Bake the PATH permanently into the image so processes can find these tools by name
ENV PATH="/root/.local/bin:${PATH}"

# Install security tools
RUN mkdir -p /opt/security-tools && \
    git clone --depth 1 https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git /opt/security-tools/anthropic-cybersecurity-skills && \
    git clone --depth 1 https://github.com/xsourabhsharma/ai-security-audit-pro.git /opt/security-tools/ai-security-audit-pro

# Start n8n when the container runs
CMD ["n8n"]
