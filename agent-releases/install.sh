
#!/bin/bash

set -e

echo "=== Ghost IT Agent — Installer ==="



PIPELINE_HOST="${GHOST_PIPELINE_HOST:-3.7.6.9}"

PIPELINE_PORT="${GHOST_PIPELINE_PORT:-9000}"

HTTP_PORT="8000"

INSTALL_DIR="/opt/ghostit"

BINARY_PATH="$INSTALL_DIR/ghostit-agent-linux-amd64"

BPF_OBJ_PATH="$INSTALL_DIR/ghost_agent.bpf.o"



if [ "$EUID" -ne 0 ]; then

    echo "ERROR: This installer must be run as root (use sudo)."

    exit 1

fi



echo "[1/6] Creating install directory..."

mkdir -p "$INSTALL_DIR"



echo "[2/6] Checking for a published release..."

VERSION_INFO=$(curl -s "http://${PIPELINE_HOST}:${HTTP_PORT}/agent/version")

AVAILABLE=$(echo "$VERSION_INFO" | grep -o '"available":[a-z]*' | cut -d: -f2)

if [ "$AVAILABLE" != "true" ]; then

    echo "ERROR: No agent release currently published on the server."

    exit 1

fi

EXPECTED_HASH=$(echo "$VERSION_INFO" | grep -o '"sha256":"[a-f0-9]*"' | cut -d'"' -f4)

VERSION=$(echo "$VERSION_INFO" | grep -o '"version":"[^"]*"' | cut -d'"' -f4)

echo "    Found version: $VERSION"



echo "[3/6] Downloading agent binary..."

curl -s "http://${PIPELINE_HOST}:${HTTP_PORT}/agent/download" -o "$BINARY_PATH"

ACTUAL_HASH=$(sha256sum "$BINARY_PATH" | cut -d' ' -f1)

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then

    echo "ERROR: Downloaded binary hash mismatch — refusing to install (possible tampering)."

    rm -f "$BINARY_PATH"

    exit 1

fi

chmod +x "$BINARY_PATH"

echo "    Verified: $ACTUAL_HASH"



echo "[4/6] Downloading eBPF kernel object..."

curl -s "http://${PIPELINE_HOST}:${HTTP_PORT}/agent/ebpf-object" -o "$BPF_OBJ_PATH"

if [ ! -s "$BPF_OBJ_PATH" ]; then

    echo "ERROR: eBPF object download failed or is empty."

    exit 1

fi



echo "[5/6] Installing systemd service..."

cat > /etc/systemd/system/ghostit-agent.service << SERVICEEOF

[Unit]

Description=Ghost IT eBPF Agent

After=network.target



[Service]

Type=simple

ExecStart=${BINARY_PATH}

Environment=GHOST_PIPELINE_HOST=${PIPELINE_HOST}

Environment=GHOST_PIPELINE_PORT=${PIPELINE_PORT}

Environment=GHOST_BPF_OBJ=${BPF_OBJ_PATH}

Restart=always

RestartSec=5

StandardOutput=journal

StandardError=journal



[Install]

WantedBy=multi-user.target

SERVICEEOF



echo "[6/6] Starting Ghost IT Agent..."

systemctl daemon-reload

systemctl enable ghostit-agent.service

systemctl restart ghostit-agent.service



sleep 5

if systemctl is-active --quiet ghostit-agent.service; then

    echo ""

    echo "=== Ghost IT Agent installed and running successfully (version $VERSION) ==="

    echo "Connected to: ${PIPELINE_HOST}:${PIPELINE_PORT}"

    echo "Check status anytime with: sudo systemctl status ghostit-agent.service"

else

    echo ""

    echo "=== WARNING: Agent installed but did not start cleanly. ==="

    echo "Check status with: sudo systemctl status ghostit-agent.service"

    echo "Check logs with: sudo journalctl -u ghostit-agent.service -n 30"

    exit 1

fi

