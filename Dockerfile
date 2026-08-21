# Run for clean rebuild: docker compose build --no-cache 

# Base image is Alpine Linux, so we can use apk to install additional packages
# https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.executecommand

FROM docker.n8n.io/n8nio/n8n:latest
USER root

# Restore the apk package manager (removed from the base image)
COPY --from=alpine:3.22 /sbin/apk /sbin/apk
COPY --from=alpine:3.22 /lib/apk /lib/apk
COPY --from=alpine:3.22 /usr/lib/libapk* /usr/lib/

# Install curl & bash
RUN apk add --no-cache curl bash

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

USER node