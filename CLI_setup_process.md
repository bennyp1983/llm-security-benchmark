# Auth methods for Codex, Claude Code, Antigravity (over SSH into n8n-uni)
ssh ben@n8n-uni
sudo docker compose exec n8n bash


## Codex ---------
cd /data/results-benchmark/codex
codex login --device-auth
### Test No thinking
codex exec --skip-git-repo-check "Respond back if you are working, with the model and thinking effort you are using."
### Test With thinking
codex exec --skip-git-repo-check \ -c 'model_reasoning_effort="medium"' \ "Respond back if you are working."


## Claude Code ---------
cd /data/results-benchmark/claude
Claude 
### Test
claude -p "Respond back if you are working, with the model and thinking effort you are using."


## Antigravity ---------
cd /data/results-benchmark/agy
agy
### Test
agy -p "Respond back if you are working, with the model and thinking effort you are using"


## Qwen ---------
cd /data/results-benchmark/qwen
Qwen
### Test
qwen --prompt "Respond back if you are working, with the model and thinking effort you are using"

