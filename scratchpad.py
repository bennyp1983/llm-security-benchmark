import hashlib
students = _items[0]["json"]["prompts_json"]["student"]
cli_settings = _items[0]["json"]["prompts_json"]["cli_settings"]

for student in students:
    for task in student["task"]:
        for p in task["prompts"]:
            p["hash"] = hashlib.sha256(p["prompt"].encode("utf-8")).hexdigest()
            p["cli_settings"] = []
            for cli in cli_settings:
                if p.get("turn"):
                    path_suffix = f'/{student["name"]}/{task["task_number"]}/{p["style"]}/{p["turn"]}/'
                else:
                    path_suffix = f'/{student["name"]}/{task["task_number"]}/{p["style"]}/'
                p["cli_settings"].append({"cli_name": cli["cli_name"], "model_choice": cli["model_choice"], "thinking_level": cli["thinking_level"], "container_path": cli["container_path"]+path_suffix})

return students