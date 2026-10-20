#!/usr/bin/env bash
# Set up the LLM security benchmark: build and start both n8n containers, import the two
# workflows, create the n8n accounts, log the coding CLIs in, or reset the results.
#
# Run:  ./setup.sh                          a menu of the options below
#       ./setup.sh install|login|reset      one option, no menu
#
# Use "sudo ./setup.sh" if your user is not in the docker group. Folders this script
# creates are still handed to you, so Docker never leaves them owned by root.


#-----------------------------------------#    settings    #-----------------------------------------#

set -u                                                               # Stop on any unset variable


#-------------------------------------#    Define constants    #-------------------------------------#

CANCEL_SELECTION="c"                                                 # Character to cancel a selected menu option

# Define the two n8n services, as named in docker-compose.yml
BENCHMARK_SERVICE="n8n"                                              # Generates the code
CYBER_SERVICE="n8n-cyber"                                            # Reviews the code and writes the reports
BENCHMARK_PORT=5678                                                  # As published in docker-compose.yml
CYBER_PORT=5688
BENCHMARK_URL="http://localhost:$BENCHMARK_PORT"                     # The script runs on the Docker machine itself
CYBER_URL="http://localhost:$CYBER_PORT"
WAIT_TRIES=90                                                        # Health checks before giving up, 2 seconds apart

# Define the workflows, as mounted read-only in each container
WORKFLOW_ID="bwqKVV0abQefK272"                                       # Both workflows keep this id
BENCHMARK_WORKFLOW="/data/n8n-workflows/benchmark/bwqKVV0abQefK272.json"
CYBER_WORKFLOW="/data/n8n-workflows/cyber/bwqKVV0abQefK272.json"

# Define the folders Docker mounts; made here first so Docker never creates them as root
MOUNT_FOLDERS=(results/agy results/claude results/codex results/qwen
               results-cyber/agy results-cyber/claude results-cyber/codex results-cyber/qwen
               report)

# Define where the results sit inside each container, for a reset
BENCHMARK_RESULTS="/data/results"
CYBER_RESULTS="/data/results-cyber"
RESET_WORD="reset"                                                   # Typed to confirm a reset

# Define n8n's owner password rules, as its own sign-up form checks them
MIN_PASSWORD_LENGTH=8

# Menu prompts and messages
WELCOME_MESSAGE="Welcome to the LLM security benchmark setup."
MENU_SELECTION_PROMPT=$'\nChoose [i]nstall, [l]ogin, [r]eset or [q]uit.'
INVALID_CHOICE="Invalid choice"
GOODBYE_MESSAGE="Goodbye!"
CANCELLED_MESSAGE="Cancelling"

# Install prompts and messages
DOCKER_MISSING="Error: Docker with the Compose plugin is required. Install it first: https://docs.docker.com/engine/install/"
DOCKER_NO_ACCESS="Error: cannot talk to Docker. Run with sudo, or add your user to the docker group."
N8N_NOT_READY="Error: n8n did not start in time. Check: docker compose logs"
EMAIL_PROMPT='n8n account email, or "'"$CANCEL_SELECTION"'" to cancel: '
FIRST_NAME_PROMPT="First name: "
LAST_NAME_PROMPT="Last name: "
PASSWORD_PROMPT="Password (8+ characters, with a number and an uppercase letter): "
PASSWORD_RULES="Error: the password needs 8+ characters, a number and an uppercase letter."
OWNERS_DONE="Both n8n instances already have an owner account."
OWNER_FALLBACK="Could not create the account automatically. Open this address and create it there:"
INSTALL_DONE="
Install finished. Open n8n in your browser:
  benchmark  http://%s:$BENCHMARK_PORT
  cyber      http://%s:$CYBER_PORT
Next: choose [l]ogin to sign the coding CLIs in."

# Login prompts and messages
CLI_SELECTION_PROMPT='Log in which CLIs? Enter numbers separated by commas (e.g. 1,3), [a]ll, or "'"$CANCEL_SELECTION"'" to cancel: '
LOGIN_HINT="Follow the CLI's own sign-in steps. Exit the CLI when it says you are signed in (e.g. /exit or Ctrl+C)."
LOGIN_DONE="Logins finished."

# Reset prompts and messages
RESET_WARNING="This deletes every generated program and review in results/ and results-cyber/.
The report files stay until the next cyber run rebuilds them."
RESET_PROMPT='Type "'"$RESET_WORD"'" to delete them, or "'"$CANCEL_SELECTION"'" to cancel: '
RESET_DONE="Results deleted. The original results come back with a fresh clone of the repository."
STACK_NOT_RUNNING="Error: the containers are not running. Choose [i]nstall first."


#-------------------------------------#    Define functions    #-------------------------------------#


# Function that stops with a clear message when Docker or Compose is missing or unreachable
check_docker_is_installed() {
    if ! command -v docker > /dev/null || ! docker compose version > /dev/null 2>&1; then
        echo "$DOCKER_MISSING"
        exit 1
    fi

    if ! docker info > /dev/null 2>&1; then
        echo "$DOCKER_NO_ACCESS"
        exit 1
    fi
}


# Function that makes every folder Docker mounts, owned by the person running the script
make_mount_folders() {
    for folder in "${MOUNT_FOLDERS[@]}"; do
        if [ -d "$folder" ]; then
            continue
        fi

        mkdir -p "$folder"

        # Under sudo, hand the new folder back to the user who ran sudo
        if [ -n "${SUDO_USER:-}" ]; then
            chown "$SUDO_USER": "$folder"
        fi
    done
}


# Function that builds both images; cyber builds on top of the benchmark image, so benchmark goes first
build_images() {
    echo "Building the benchmark image..."
    docker compose build "$BENCHMARK_SERVICE" || exit 1

    echo "Building the cyber image..."
    docker compose build "$CYBER_SERVICE" || exit 1
}


# Function that starts both n8n instances and their task runners
start_containers() {
    docker compose up -d || exit 1
}


# Function that waits until an n8n instance answers its health check
wait_for_n8n() {
    local url="$1"

    for (( try = 1; try <= WAIT_TRIES; try++ )); do
        if curl -fs "$url/healthz" > /dev/null; then
            return 0
        fi
        sleep 2
    done

    echo "$N8N_NOT_READY"
    exit 1
}


# Function that tells whether a workflow is already in an n8n instance
workflow_exists() {
    local service="$1"

    docker compose exec -T "$service" n8n list:workflow --onlyId 2> /dev/null | grep -qx "$WORKFLOW_ID"
}


# Function that imports a workflow file into one n8n instance, unless it is already there
import_workflow() {
    local service="$1"
    local workflow_file="$2"

    # An existing workflow is left alone, so changes made in the n8n editor are never overwritten
    if workflow_exists "$service"; then
        echo "The $service workflow is already in n8n, left as it is."
        return 0
    fi

    docker compose exec -T "$service" n8n import:workflow --input="$workflow_file" || exit 1
    echo "Imported the $service workflow."
}


# Function that imports the benchmark and cyber workflows into their own n8n instance
import_workflows() {
    import_workflow "$BENCHMARK_SERVICE" "$BENCHMARK_WORKFLOW"
    import_workflow "$CYBER_SERVICE" "$CYBER_WORKFLOW"
}


# Function that tells whether an n8n instance still shows its first-run owner sign-up
needs_owner_account() {
    local url="$1"

    curl -fs "$url/rest/settings" | grep -q '"showSetupOnFirstLoad":true'
}


# Function that escapes text for a JSON string: backslashes first, then double quotes
json_text() {
    local text="${1//\\/\\\\}"
    text="${text//\"/\\\"}"
    printf '%s' "$text"
}


# Function that checks a password against n8n's rules: length, a number and an uppercase letter
password_is_valid() {
    local password="$1"

    [ "${#password}" -ge "$MIN_PASSWORD_LENGTH" ] && [[ "$password" =~ [0-9] ]] && [[ "$password" =~ [A-Z] ]]
}


# Function that asks once for the owner account details used on both n8n instances.
# Returns 1 if the user cancels
ask_owner_details() {
    read -rp "$EMAIL_PROMPT" OWNER_EMAIL
    if [ "$OWNER_EMAIL" = "$CANCEL_SELECTION" ] || [ -z "$OWNER_EMAIL" ]; then
        echo "$CANCELLED_MESSAGE"
        return 1
    fi

    read -rp "$FIRST_NAME_PROMPT" OWNER_FIRST_NAME
    read -rp "$LAST_NAME_PROMPT" OWNER_LAST_NAME

    # Ask again until the password meets n8n's rules
    while true; do
        read -rsp "$PASSWORD_PROMPT" OWNER_PASSWORD
        echo
        if password_is_valid "$OWNER_PASSWORD"; then
            return 0
        fi
        echo "$PASSWORD_RULES"
    done
}


# Function that creates the owner account on one n8n instance, as its first-run sign-up form does
create_owner_account() {
    local url="$1"
    local account_json

    account_json="$(printf '{"email":"%s","firstName":"%s","lastName":"%s","password":"%s"}' \
        "$(json_text "$OWNER_EMAIL")" \
        "$(json_text "$OWNER_FIRST_NAME")" \
        "$(json_text "$OWNER_LAST_NAME")" \
        "$(json_text "$OWNER_PASSWORD")")"

    # Sent on stdin (-d @-), so the password never shows in the process list
    if printf '%s' "$account_json" | curl -fs -X POST -H "Content-Type: application/json" -d @- \
            "$url/rest/owner/setup" > /dev/null; then
        echo "Created the n8n account at $url"
    else
        # Shown with this machine's address, which also works from another computer
        echo "$OWNER_FALLBACK ${url/localhost/$(machine_address)}"
    fi
}


# Function that creates the owner account on each n8n instance that does not have one yet
create_owner_accounts() {
    local urls_needing_owner=()

    for url in "$BENCHMARK_URL" "$CYBER_URL"; do
        if needs_owner_account "$url"; then
            urls_needing_owner+=("$url")
        fi
    done

    if [ "${#urls_needing_owner[@]}" -eq 0 ]; then
        echo "$OWNERS_DONE"
        return 0
    fi

    if ! ask_owner_details; then
        return 0
    fi

    for url in "${urls_needing_owner[@]}"; do
        create_owner_account "$url"
    done
}


# Function that prints each configured CLI as "name|login command", read from config/benchmark.json
configured_clis() {
    docker compose exec -T "$BENCHMARK_SERVICE" python3 -c '
import json
for cli in json.load(open("/data/config/benchmark.json"))["cli_settings"]:
    print(cli["name"] + "|" + cli.get("login", ""))'
}


# Function that runs one CLI login, interactively, in one container
login_to_cli() {
    local service="$1"
    local cli_name="$2"
    local login_command="$3"

    echo
    echo "=== $cli_name in $service ==="
    echo "$LOGIN_HINT"
    docker compose exec -it "$service" sh -c "$login_command"
}


# Function that turns a comma-separated choice like "1,3" into CLI positions in CHOSEN.
# Returns 1 if any part is not a listed number
read_cli_numbers() {
    local choice="$1"
    local cli_count="$2"
    local parts=()

    CHOSEN=()

    # Nothing entered is not a choice
    if [ -z "${choice// /}" ]; then
        return 1
    fi

    IFS="," read -ra parts <<< "$choice"

    for part in "${parts[@]}"; do
        local number="${part// /}"

        if ! [[ "$number" =~ ^[0-9]+$ ]] || [ "$number" -lt 1 ] || [ "$number" -gt "$cli_count" ]; then
            return 1
        fi
        CHOSEN+=("$(( number - 1 ))")
    done
}


# Function that asks which configured CLIs to log in, then logs each in on both containers
login_to_clis() {
    local cli_names=()
    local cli_logins=()

    # The configured CLIs, numbered from 1 for the user
    while IFS="|" read -r cli_name login_command; do
        cli_names+=("$cli_name")
        cli_logins+=("$login_command")
    done < <(configured_clis)

    for index in "${!cli_names[@]}"; do
        echo "$(( index + 1 ))) ${cli_names[$index]}"
    done
    read -rp "$CLI_SELECTION_PROMPT" choice

    if [ "$choice" = "$CANCEL_SELECTION" ]; then
        echo "$CANCELLED_MESSAGE"
        return 0
    elif [ "$choice" = "a" ]; then
        CHOSEN=("${!cli_names[@]}")
    elif ! read_cli_numbers "$choice" "${#cli_names[@]}"; then
        echo "$INVALID_CHOICE"
        return 0
    fi

    # Each container keeps its own logins, so every chosen CLI signs in on both
    for index in "${CHOSEN[@]}"; do
        for service in "$BENCHMARK_SERVICE" "$CYBER_SERVICE"; do
            login_to_cli "$service" "${cli_names[$index]}" "${cli_logins[$index]}"
        done
    done

    echo "$LOGIN_DONE"
}


# Function that tells whether both n8n containers are running
containers_are_running() {
    local running

    running="$(docker compose ps --status running --services)"
    grep -qx "$BENCHMARK_SERVICE" <<< "$running" && grep -qx "$CYBER_SERVICE" <<< "$running"
}


# Function that empties every results folder but keeps the folders, from inside the containers,
# where root can delete root-owned results. Returns early if the user does not confirm
reset_results() {
    if ! containers_are_running; then
        echo "$STACK_NOT_RUNNING"
        return 0
    fi

    echo "$RESET_WARNING"
    read -rp "$RESET_PROMPT" confirm
    if [ "$confirm" != "$RESET_WORD" ]; then
        echo "$CANCELLED_MESSAGE"
        return 0
    fi

    # Everything inside each CLI's folder goes, the folder itself stays mounted
    docker compose exec -T "$BENCHMARK_SERVICE" find "$BENCHMARK_RESULTS" -mindepth 2 -maxdepth 2 -exec rm -rf {} +
    docker compose exec -T "$CYBER_SERVICE" find "$CYBER_RESULTS" -mindepth 2 -maxdepth 2 -exec rm -rf {} +

    echo "$RESET_DONE"
}


# Function that returns this machine's network address, for opening n8n from another
# computer (a headless server); localhost when no address can be found
machine_address() {
    local address

    address="$(hostname -I 2> /dev/null | awk '{print $1}')"
    if [ -z "$address" ]; then
        address="localhost"
    fi
    printf '%s' "$address"
}


# Function that installs or updates everything a fresh clone needs before its first run
install_stack() {
    check_docker_is_installed
    make_mount_folders
    build_images
    start_containers
    wait_for_n8n "$BENCHMARK_URL"
    wait_for_n8n "$CYBER_URL"
    import_workflows
    create_owner_accounts
    local address
    address="$(machine_address)"

    # shellcheck disable=SC2059 # The message is the format: it holds the two %s for the address
    printf "$INSTALL_DONE\n" "$address" "$address"
}


#-------------------------------------#    Main execution of program    #-------------------------------------#

# Work from the repository folder, where docker-compose.yml is
cd "$(dirname "$0")" || exit 1

# One option named on the command line runs on its own, without the menu
if [ "$#" -gt 0 ]; then
    case "$1" in
        install) install_stack ;;
        login)   check_docker_is_installed; login_to_clis ;;
        reset)   check_docker_is_installed; reset_results ;;
        *)       echo "$INVALID_CHOICE: $1 (use install, login or reset)"; exit 1 ;;
    esac
    exit 0
fi

echo "$WELCOME_MESSAGE"

while true; do
    # Show menu options, requesting a selection from the user
    echo "$MENU_SELECTION_PROMPT"
    read -rp "> " choice

    # Build, start, import the workflows and create the n8n accounts
    if [ "$choice" = "i" ]; then
        install_stack

    # Sign the coding CLIs in, in both containers
    elif [ "$choice" = "l" ]; then
        check_docker_is_installed
        login_to_clis

    # Delete every generated program and review, keeping the folders
    elif [ "$choice" = "r" ]; then
        check_docker_is_installed
        reset_results

    # Quit the program
    elif [ "$choice" = "q" ]; then
        echo "$GOODBYE_MESSAGE"
        break

    else
        echo "$INVALID_CHOICE"
    fi
done
