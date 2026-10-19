
#!/usr/bin/env bash
set -Eeuo pipefail

# Usage:
#   sudo ./deploy.sh <graylog-host> [graylog-port]
#
# Example:
#   sudo ./deploy.sh logmon.ipa.psati.ru 12311

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc"
STATE_DIR="/var/lib/cups-graylog"
SYSTEMD_DIR="/etc/systemd/system"

AGENT_NAME="cups-graylog.py"
CONFIG_FILE="${CONFIG_DIR}/cups-graylog.conf"
SERVICE_FILE="${SYSTEMD_DIR}/cups-graylog.service"
TIMER_FILE="${SYSTEMD_DIR}/cups-graylog.timer"

GRAYLOG_HOST="${1:-}"
GRAYLOG_PORT="${2:-12201}"

log() {
    printf '[cups-graylog-deploy] %s\n' "$*"
}

die() {
    log "ERROR: $*"
    exit 1
}

# ------------------------------------------------------------
# Preconditions
# ------------------------------------------------------------

if [[ "${EUID}" -ne 0 ]]; then
    die "Run this script as root: sudo ./deploy.sh HOST [PORT]"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_AGENT="${SCRIPT_DIR}/${AGENT_NAME}"

[[ -f "$SOURCE_AGENT" ]] ||
    die "Agent not found: ${SOURCE_AGENT}"

[[ -n "$GRAYLOG_HOST" ]] ||
    die "Usage: $0 <graylog-host> [graylog-port]"

[[ "$GRAYLOG_HOST" =~ ^[A-Za-z0-9.:-]+$ ]] ||
    die "Invalid Graylog hostname or address"

[[ "$GRAYLOG_PORT" =~ ^[0-9]+$ ]] ||
    die "Graylog port must be numeric"

(( GRAYLOG_PORT >= 1 && GRAYLOG_PORT <= 65535 )) ||
    die "Graylog port must be between 1 and 65535"

command -v python3 >/dev/null ||
    die "python3 is not installed"

command -v systemctl >/dev/null ||
    die "systemd is not available"

command -v journalctl >/dev/null ||
    die "journalctl is not available"

systemctl cat cups.service >/dev/null 2>&1 ||
    die "cups.service was not found"

# ------------------------------------------------------------
# Validate Python syntax before installing
# ------------------------------------------------------------

log "Checking Python syntax..."

python3 -m py_compile "$SOURCE_AGENT" ||
    die "Python syntax check failed"

# ------------------------------------------------------------
# Install agent and directories
# ------------------------------------------------------------

log "Creating directories..."

install -d -o root -g root -m 755 "$INSTALL_DIR"
install -d -o root -g root -m 700 "$STATE_DIR"

log "Installing agent..."

install -o root -g root -m 755 \
    "$SOURCE_AGENT" \
    "${INSTALL_DIR}/${AGENT_NAME}"

# ------------------------------------------------------------
# Configure Graylog
# ------------------------------------------------------------

log "Writing Graylog configuration..."

cat > "$CONFIG_FILE" <<EOF
GRAYLOG_GELF_HOST=${GRAYLOG_HOST}
GRAYLOG_GELF_PORT=${GRAYLOG_PORT}
EOF

chown root:root "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"

# ------------------------------------------------------------
# Create systemd service
# ------------------------------------------------------------

log "Creating systemd service..."

cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=CUPS GELF UDP Sender
After=network-online.target cups.service
Wants=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=/etc/cups-graylog.conf
ExecStart=/usr/bin/python3 /usr/local/bin/cups-graylog.py
TimeoutStartSec=50
UMask=0077
EOF

chown root:root "$SERVICE_FILE"
chmod 644 "$SERVICE_FILE"

# ------------------------------------------------------------
# Create systemd timer
# ------------------------------------------------------------

log "Creating systemd timer..."

cat > "$TIMER_FILE" <<'EOF'
[Unit]
Description=Run CUPS GELF UDP Sender periodically

[Timer]
OnBootSec=30s
OnUnitActiveSec=1min
AccuracySec=5s
Persistent=true
Unit=cups-graylog.service

[Install]
WantedBy=timers.target
EOF

chown root:root "$TIMER_FILE"
chmod 644 "$TIMER_FILE"

# ------------------------------------------------------------
# Enable and start
# ------------------------------------------------------------

log "Reloading systemd..."

systemctl daemon-reload

log "Enabling timer..."

systemctl enable --now cups-graylog.timer

log "Running initial agent execution..."

if systemctl start cups-graylog.service; then
    log "Initial execution completed."
else
    log "WARNING: initial execution failed."
    log "Inspect logs with: journalctl -u cups-graylog.service -n 100"
fi

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

log "Deployment finished."
log "Graylog: ${GRAYLOG_HOST}:${GRAYLOG_PORT}"
log "Agent: ${INSTALL_DIR}/${AGENT_NAME}"
log "Config: ${CONFIG_FILE}"
log "State: ${STATE_DIR}/state.json"
log "Timer: enabled"

systemctl status cups-graylog.timer --no-pager || true
