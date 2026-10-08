#!/usr/bin/env bash

set -euo pipefail

OMNI_VERSION="${OMNI_VERSION:-latest}"
OMNI_URL="${OMNI_URL:-}"
OMNI_INSTALL_PATH="${OMNI_INSTALL_PATH:-/usr/local/bin/}"
OMNI_INSTALL_SYSTEMD_DIR="${OMNI_INSTALL_SYSTEMD_DIR:-/etc/systemd/system/}"
OMNI_INSTALL_LAUNCHD_DIR="${OMNI_INSTALL_LAUNCHD_DIR:-/Library/LaunchDaemons/}"
OMNI_SKIP_DOWNLOAD="${OMNI_SKIP_DOWNLOAD:-false}"
OMNI_ARTIFACT_API_TOKEN="${OMNI_ARTIFACT_API_TOKEN:-}"
OMNI_TRIGGER_IMMEDIATELY="${OMNI_RUN_IMMEDIATELY:-true}"
OMNI_SKIP_DB_DOWNLOAD="${OMNI_SKIP_DB_DOWNLOAD:-false}"
DEFAULT_VULN_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db
DEFAULT_JAVA_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-java-db
OMNI_VULN_DB_REPOSITORY="${OMNI_VULN_DB_REPOSITORY:-$DEFAULT_VULN_DB_REPOSITORY}"
OMNI_JAVA_DB_REPOSITORY="${OMNI_JAVA_DB_REPOSITORY:-$DEFAULT_JAVA_DB_REPOSITORY}"
OMNI_HOME_DIR="${OMNI_HOME_DIR:-/var/lib/accuknox-omni/}"
OMNI_SKIP_MALWARE_SCAN="${OMNI_SKIP_MALWARE_SCAN:-true}"
OMNI_MAX_MEMORY="${OMNI_MAX_MEMORY:-2G}"
OMNI_CPU_QUOTA="${OMNI_CPU_QUOTA:-10%}"

LAUNCHD_LABEL=com.accuknox.omni

info() {
    echo '[INFO]' "$@"
}

fatal() {
    echo '[ERROR]' "$@" >&2
    exit 1
}

is_true() {
    [[ $1 == true || $1 == 1 ]]
}

is_false() {
    [[ $1 == false || $1 == 0 ]]
}

quote() {
    for arg in "$@"; do
        printf '%s\n' "$arg" | sed "s/'/'\\\\''/g;1s/^/'/;\$s/\$/'/"
    done
}

quote_indent() {
    local i=1 last=$#
    for arg in "$@"; do
        if (( i == 1 )); then
            printf ' \\\n'
        fi
        if (( i < last )); then
            printf '\t%s \\\n' "$(quote "$arg")"
        else
            printf '\t%s\n' "$(quote "$arg")"
        fi
        ((i++))
    done
}

xml_escape() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g'
}

filepath_join() {
    local path="" part
    for part in "$@"; do
        path="${path%/}"
        if [[ -n $path && $part == /* ]]; then
            part="${part#/}"
        fi
        path="${path:+$path/}$part"
    done
    echo "$path"
}

download() {
    [[ $# -eq 2 ]] || fatal 'Download needs exactly 2 arguments'

    local status=1
    set +e
    case $DOWNLOADER in
        curl)
            curl -o "$1" -sfL "$2"
            status=$?
            ;;
        wget)
            wget -qO "$1" "$2"
            status=$?
            ;;
        *)
            set -e
            fatal "Incorrect executable '$DOWNLOADER'"
            ;;
    esac
    set -e

    [[ $status -eq 0 ]] || fatal 'Download failed'
}

verify_systemd() {
    if [[ -x /bin/systemctl ]] || type systemctl >/dev/null 2>&1; then
        return
    fi
    fatal 'Can not find systemd to use as a process supervisor for omni'
}

verify_launchd() {
    type launchctl >/dev/null 2>&1 || fatal 'Can not find launchctl'
    type plutil >/dev/null 2>&1 || fatal 'Can not find plutil'
}

verify_omni_url() {
    case $OMNI_URL in
        http://* | https://*)
            ;;
        *)
            fatal "Only HTTP(S) URLs are supported for OMNI_URL: $OMNI_URL"
            ;;
    esac
}

verify_omni_is_executable() {
    if [[ ! -x $OMNI_BIN_PATH ]]; then
        fatal "Executable omni binary not found at $OMNI_BIN_PATH"
    fi
}

setup_verify_downloader() {
    [[ -x $(command -v "$1") ]] || return 1

    DOWNLOADER=$1
}

setup_os() {
    case $(uname -s) in
        Linux)
            OS=linux
            ROOT_GROUP=root
            ;;
        Darwin)
            OS=darwin
            ROOT_GROUP=wheel
            ;;
        *)
            fatal "Unsupported operating system $(uname -s)"
            ;;
    esac
    info "Host operating system $OS"
}

setup_arch() {
    case $(uname -m) in
        amd64 | x86_64)
            ARCH=amd64
            ;;
        arm64 | aarch64)
            ARCH=arm64
            ;;
        *)
            fatal "Unsupported architecture $(uname -m)"
            ;;
    esac
    info "Host architecture $ARCH"
}

setup_env() {
    SUDO=sudo
    if [[ $(id -u) -eq 0 ]]; then
        SUDO=
    fi

    setup_os
    setup_verify_downloader curl || setup_verify_downloader wget || \
        fatal 'Can not find curl or wget for downloading files'
    setup_arch

    if [[ -z $OMNI_URL ]]; then
        OMNI_URL="https://accuknox-omni.s3.us-east-1.amazonaws.com/"
        OMNI_URL="${OMNI_URL}${OMNI_VERSION}/omni-${OS}-${ARCH}"
    fi

    if [[ -z $OMNI_ARTIFACT_API_TOKEN ]]; then
        read -rsp 'Enter artifact API token: ' OMNI_ARTIFACT_API_TOKEN
        echo
        [[ -n $OMNI_ARTIFACT_API_TOKEN ]] || \
            fatal 'OMNI_ARTIFACT_API_TOKEN cannot be empty'
    fi

    OMNI_BIN_PATH="$(filepath_join "$OMNI_INSTALL_PATH" omni)"
    TOKEN_FILE="$(filepath_join "$OMNI_HOME_DIR" artifact.tok)"
    FILE_UNINSTALL_SCRIPT="$(filepath_join \
        "$OMNI_INSTALL_PATH" omni-uninstall.sh)"

    DB_DOWNLOAD_CMD_EXEC="db download vuln java aiagent$(quote_indent \
        --vuln-db-repository="$OMNI_VULN_DB_REPOSITORY" \
        --java-db-repository="$OMNI_JAVA_DB_REPOSITORY" \
        --destination="$OMNI_HOME_DIR")"
    AGENT_CMD_EXEC="agent scan$(quote_indent \
        --artifact-token-file="$TOKEN_FILE" \
        --vuln-db-directory="$OMNI_HOME_DIR" "$@")"
    if is_true "$OMNI_SKIP_MALWARE_SCAN"; then
        AGENT_CMD_EXEC="$AGENT_CMD_EXEC --skip-malware-scan"
    fi

    FILE_OMNI_SERVICE="$(filepath_join \
        "$OMNI_INSTALL_SYSTEMD_DIR" omni.service)"
    FILE_OMNI_TIMER="$(filepath_join \
        "$OMNI_INSTALL_SYSTEMD_DIR" omni.timer)"
    FILE_OMNI_PLIST="$(filepath_join \
        "$OMNI_INSTALL_LAUNCHD_DIR" "$LAUNCHD_LABEL.plist")"
    FILE_OMNI_RUNNER="$(filepath_join "$OMNI_INSTALL_PATH" omni-run.sh)"
    FILE_OMNI_STDOUT="$(filepath_join "$OMNI_HOME_DIR" omni.log)"
    FILE_OMNI_STDERR="$(filepath_join "$OMNI_HOME_DIR" omni.err.log)"
}

setup_tmp() {
    TMP_DIR=$(mktemp -d -t omni-install.XXXXXXXXXX)
    TMP_BIN=${TMP_DIR}/omni.bin
    cleanup() {
        local code=$?
        set +e
        trap - EXIT
        rm -rf "${TMP_DIR}"
        exit "$code"
    }
    trap cleanup INT EXIT
}

setup_token() {
    $SUDO mkdir -p "$OMNI_HOME_DIR"
    info "Saving token at $TOKEN_FILE"
    printf '%s\n' "$OMNI_ARTIFACT_API_TOKEN" | \
        $SUDO tee "$TOKEN_FILE" >/dev/null
    $SUDO chown -R "root:$ROOT_GROUP" "$OMNI_HOME_DIR"
    $SUDO chmod 600 "$TOKEN_FILE"
}

download_binary() {
    info "Downloading binary from $OMNI_URL"
    download "$TMP_BIN" "$OMNI_URL"

    info "Installing binary at $OMNI_BIN_PATH"
    $SUDO mkdir -p "$OMNI_INSTALL_PATH"
    $SUDO mv "$TMP_BIN" "$OMNI_BIN_PATH"
    $SUDO chown "root:$ROOT_GROUP" "$OMNI_BIN_PATH"
    $SUDO chmod 755 "$OMNI_BIN_PATH"
}

create_systemd_service_file() {
    info "Creating systemd service file $FILE_OMNI_SERVICE"
    {
        echo '[Unit]'
        echo 'Description=AccuKnox Omni'
        echo 'After=network-online.target'
        echo 'Wants=network-online.target'
        echo
        echo '[Install]'
        echo 'WantedBy=multi-user.target'
        echo
        echo '[Service]'
        echo 'Type=simple'
        echo 'TimeoutStartSec=infinity'
        echo 'User=root'
        echo "CPUQuota=$OMNI_CPU_QUOTA"
        echo "MemoryMax=$OMNI_MAX_MEMORY"
        echo 'StandardOutput=journal'
        echo 'StandardError=journal'
        echo 'SyslogIdentifier=accuknox-omni'
        if ! is_true "$OMNI_SKIP_DB_DOWNLOAD"; then
            echo "ExecStartPre=$OMNI_BIN_PATH $DB_DOWNLOAD_CMD_EXEC"
            if is_false "$OMNI_SKIP_MALWARE_SCAN" && \
                [[ -x $(command -v freshclam) ]]; then
                echo "ExecStartPre=$(command -v freshclam)"
            fi
        fi
        echo "ExecStart=$OMNI_BIN_PATH $AGENT_CMD_EXEC"
    } | $SUDO tee "$FILE_OMNI_SERVICE" >/dev/null
}

create_systemd_timer_file() {
    info "Creating systemd timer file $FILE_OMNI_TIMER"
    {
        echo '[Unit]'
        echo 'Description=Run AccuKnox Omni periodically'
        echo 'After=omni.service'
        echo
        echo '[Timer]'
        echo 'OnCalendar=daily'
        echo 'Persistent=true'
        echo 'AccuracySec=1h'
        echo 'RandomizedDelaySec=10m'
        echo
        echo '[Install]'
        echo 'WantedBy=timers.target'
    } | $SUDO tee "$FILE_OMNI_TIMER" >/dev/null
}

create_systemd_uninstall_script() {
    info "Creating uninstall script $FILE_UNINSTALL_SCRIPT"
    {
        echo '#!/usr/bin/env bash'
        echo
        echo 'set -euo pipefail'
        echo
        echo 'SUDO=sudo'
        echo '[[ $(id -u) -eq 0 ]] && SUDO='
        echo '$SUDO systemctl disable omni.timer omni.service --now' \
            '2>/dev/null || true'
        printf '$SUDO rm -rf %s %s %s %s %s\n' \
            "$(quote "$FILE_OMNI_SERVICE")" \
            "$(quote "$FILE_OMNI_TIMER")" \
            "$(quote "$OMNI_BIN_PATH")" \
            "$(quote "$OMNI_HOME_DIR")" \
            "$(quote "$FILE_UNINSTALL_SCRIPT")"
    } | $SUDO tee "$FILE_UNINSTALL_SCRIPT" >/dev/null
    $SUDO chmod 755 "$FILE_UNINSTALL_SCRIPT"
}

memory_bytes() {
    if [[ ! $OMNI_MAX_MEMORY =~ ^([0-9]+)([KkMmGgTt]?)$ ]]; then
        fatal 'OMNI_MAX_MEMORY must be bytes or use a K, M, G, or T suffix'
    fi

    local value=${BASH_REMATCH[1]}
    case ${BASH_REMATCH[2]} in
        K | k)
            value=$((value * 1024))
            ;;
        M | m)
            value=$((value * 1024 * 1024))
            ;;
        G | g)
            value=$((value * 1024 * 1024 * 1024))
            ;;
        T | t)
            value=$((value * 1024 * 1024 * 1024 * 1024))
            ;;
    esac
    (( value > 0 )) || fatal 'OMNI_MAX_MEMORY must be greater than zero'
    echo "$value"
}

cpu_seconds() {
    if [[ ! $OMNI_CPU_QUOTA =~ ^([0-9]+)%$ ]]; then
        fatal 'OMNI_CPU_QUOTA must be a positive whole-number percentage'
    fi

    local value=${BASH_REMATCH[1]}
    (( value > 0 )) || fatal 'OMNI_CPU_QUOTA must be greater than zero'
    echo $((value * 864))
}

create_launchd_runner() {
    info "Creating launchd runner $FILE_OMNI_RUNNER"
    {
        echo '#!/usr/bin/env bash'
        echo
        echo 'set -euo pipefail'
        echo
        if ! is_true "$OMNI_SKIP_DB_DOWNLOAD"; then
            printf '%s %s\n' "$(quote "$OMNI_BIN_PATH")" \
                "$DB_DOWNLOAD_CMD_EXEC"
            if is_false "$OMNI_SKIP_MALWARE_SCAN" && \
                [[ -x $(command -v freshclam) ]]; then
                quote "$(command -v freshclam)"
            fi
        fi
        printf 'exec %s %s\n' "$(quote "$OMNI_BIN_PATH")" \
            "$AGENT_CMD_EXEC"
    } | $SUDO tee "$FILE_OMNI_RUNNER" >/dev/null
    $SUDO chown "root:$ROOT_GROUP" "$FILE_OMNI_RUNNER"
    $SUDO chmod 755 "$FILE_OMNI_RUNNER"
}

create_launchd_plist() {
    local cpu memory
    cpu=$(cpu_seconds)
    memory=$(memory_bytes)

    info "Creating launchd plist $FILE_OMNI_PLIST"
    $SUDO mkdir -p "$OMNI_INSTALL_LAUNCHD_DIR"
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
        echo '  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0">'
        echo '<dict>'
        echo '  <key>Label</key>'
        printf '  <string>%s</string>\n' \
            "$(xml_escape "$LAUNCHD_LABEL")"

        echo '  <key>ProgramArguments</key>'
        echo '  <array>'
        printf '    <string>%s</string>\n' \
            "$(xml_escape "$FILE_OMNI_RUNNER")"
        echo '  </array>'
        echo '  <key>WorkingDirectory</key>'
        printf '  <string>%s</string>\n' \
            "$(xml_escape "$OMNI_HOME_DIR")"

        echo '  <key>EnvironmentVariables</key>'
        echo '  <dict>'
        echo '    <key>PATH</key>'
        printf '    <string>%s%s</string>\n' \
            '/opt/homebrew/bin:/usr/local/bin:' \
            '/usr/bin:/bin:/usr/sbin:/sbin'
        echo '  </dict>'
        echo '  <key>StartCalendarInterval</key>'
        echo '  <dict>'
        echo '    <key>Hour</key>'
        echo '    <integer>0</integer>'
        echo '    <key>Minute</key>'
        echo '    <integer>0</integer>'
        echo '  </dict>'
        echo '  <key>ProcessType</key>'
        echo '  <string>Background</string>'
        echo '  <key>SoftResourceLimits</key>'
        echo '  <dict>'
        echo '    <key>CPU</key>'
        printf '    <integer>%s</integer>\n' "$cpu"
        echo '    <key>ResidentSetSize</key>'
        printf '    <integer>%s</integer>\n' "$memory"
        echo '  </dict>'
        echo '  <key>HardResourceLimits</key>'
        echo '  <dict>'
        echo '    <key>CPU</key>'
        printf '    <integer>%s</integer>\n' "$cpu"
        echo '    <key>ResidentSetSize</key>'
        printf '    <integer>%s</integer>\n' "$memory"
        echo '  </dict>'
        echo '  <key>StandardOutPath</key>'
        printf '  <string>%s</string>\n' \
            "$(xml_escape "$FILE_OMNI_STDOUT")"

        echo '  <key>StandardErrorPath</key>'
        printf '  <string>%s</string>\n' \
            "$(xml_escape "$FILE_OMNI_STDERR")"

        echo '</dict>'
        echo '</plist>'
    } | $SUDO tee "$FILE_OMNI_PLIST" >/dev/null
    $SUDO chown "root:$ROOT_GROUP" "$FILE_OMNI_PLIST"
    $SUDO chmod 644 "$FILE_OMNI_PLIST"
    $SUDO plutil -lint "$FILE_OMNI_PLIST" >/dev/null
}

create_launchd_uninstall_script() {
    info "Creating uninstall script $FILE_UNINSTALL_SCRIPT"
    {
        echo '#!/usr/bin/env bash'
        echo
        echo 'set -euo pipefail'
        echo
        echo 'SUDO=sudo'
        echo '[[ $(id -u) -eq 0 ]] && SUDO='
        printf '$SUDO launchctl bootout %s 2>/dev/null || true\n' \
            "$(quote "system/$LAUNCHD_LABEL")"
        printf '$SUDO rm -rf %s %s %s %s %s\n' \
            "$(quote "$FILE_OMNI_PLIST")" \
            "$(quote "$FILE_OMNI_RUNNER")" \
            "$(quote "$OMNI_BIN_PATH")" \
            "$(quote "$OMNI_HOME_DIR")" \
            "$(quote "$FILE_UNINSTALL_SCRIPT")"
    } | $SUDO tee "$FILE_UNINSTALL_SCRIPT" >/dev/null
    $SUDO chown "root:$ROOT_GROUP" "$FILE_UNINSTALL_SCRIPT"
    $SUDO chmod 755 "$FILE_UNINSTALL_SCRIPT"
}

install_systemd() {
    verify_systemd
    info 'Stopping existing timer and service, if present'
    $SUDO systemctl disable omni.timer omni.service --now \
        2>/dev/null || true

    create_systemd_uninstall_script
    create_systemd_service_file
    create_systemd_timer_file

    info 'Enabling timer and service'
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable omni.service
    $SUDO systemctl enable omni.timer --now
    if ! is_false "$OMNI_TRIGGER_IMMEDIATELY"; then
        info 'Starting scan'
        $SUDO systemctl restart omni.service
    fi
}

install_launchd() {
    verify_launchd
    info 'Stopping existing launchd job, if present'
    $SUDO launchctl bootout "system/$LAUNCHD_LABEL" \
        2>/dev/null || true

    create_launchd_runner
    create_launchd_uninstall_script
    create_launchd_plist

    info 'Loading launchd job'
    $SUDO launchctl bootstrap system "$FILE_OMNI_PLIST"
    if ! is_false "$OMNI_TRIGGER_IMMEDIATELY"; then
        info 'Starting scan'
        $SUDO launchctl kickstart "system/$LAUNCHD_LABEL"
    fi
}

main() {
    setup_env "$@"
    verify_omni_url
    setup_tmp
    setup_token

    if ! is_true "$OMNI_SKIP_DOWNLOAD"; then
        download_binary
    fi
    verify_omni_is_executable

    case $OS in
        linux)
            install_systemd
            ;;
        darwin)
            install_launchd
            ;;
    esac
}

main "$@"
