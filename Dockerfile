# Run for clean rebuild: docker compose build --no-cache 

# Base image is Alpine Linux, so we can use apk to install additional packages
# https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.executecommand

   FROM docker.n8n.io/n8nio/n8n:latest
   USER root

   # Restore the apk package manager (removed from the base image)
   COPY --from=alpine:3.22 /sbin/apk /sbin/apk
   COPY --from=alpine:3.22 /lib/apk /lib/apk
   COPY --from=alpine:3.22 /usr/lib/libapk* /usr/lib/

#    RUN apk add --no-cache curl
#    Run apk add --no-cache Antigravity CLI, Codex, claude code & qwen...
    USER node