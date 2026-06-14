#!/bin/bash
# Ghost IT — One Command Startup
# Usage: ./start.sh

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ◈ Ghost IT — Autonomous Digital Immune System"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Install Docker first."
    exit 1
fi

# Note: eBPF agent requires root and runs on host
echo "⚡ Starting Ghost IT stack..."
docker compose up -d --build

echo ""
echo "✅ Ghost IT is running:"
echo "   Dashboard  → http://localhost:3000"
echo "   API        → http://localhost:8000"
echo "   Canary     → http://localhost:8080"
echo ""
echo "⚠  eBPF agent requires root — start manually:"
echo "   cd agent/ebpf && sudo ./ghost_agent | python3 python/agent.py"
echo ""
echo "Logs: docker compose logs -f"
