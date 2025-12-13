#!/bin/bash
#
# Deploy Security Scanner Web UI to VISION Server
#
# This sets up the web UI on port 9093 with a systemd service
#
# Usage:
#   sudo ./deploy-vision.sh
#

set -euo pipefail

# Configuration
PORT=9093
SERVICE_NAME="security-scanner"
INSTALL_DIR="/opt/security-scanner"
WEB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../web" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

echo ""
echo -e "${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     🛡️  Security Scanner Web UI - VISION Deployment        ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    exit 1
fi

# Check Node.js
echo -e "${CYAN}1. Checking Node.js...${NC}"
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js not installed${NC}"
    exit 1
fi
NODE_VERSION=$(node --version)
echo -e "   ${GREEN}✓${NC} Node.js $NODE_VERSION"

# Check pnpm
echo -e "${CYAN}2. Checking pnpm...${NC}"
if ! command -v pnpm &> /dev/null; then
    echo -e "${YELLOW}   Installing pnpm...${NC}"
    npm install -g pnpm
fi
echo -e "   ${GREEN}✓${NC} pnpm installed"

# Create install directory
echo -e "${CYAN}3. Creating installation directory...${NC}"
mkdir -p "$INSTALL_DIR"
echo -e "   ${GREEN}✓${NC} $INSTALL_DIR"

# Copy web app
echo -e "${CYAN}4. Copying web application...${NC}"
cp -r "$WEB_DIR"/* "$INSTALL_DIR/"
echo -e "   ${GREEN}✓${NC} Files copied"

# Create Node adapter config
echo -e "${CYAN}5. Configuring for Node.js server...${NC}"
cat > "$INSTALL_DIR/astro.config.mjs" << 'EOF'
// @ts-check
import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import tailwindcss from '@tailwindcss/vite';
import node from '@astrojs/node';

// VISION Server configuration
export default defineConfig({
  integrations: [react()],
  
  vite: {
    plugins: [tailwindcss()]
  },
  
  output: 'server',
  adapter: node({
    mode: 'standalone'
  }),
  
  server: {
    host: '0.0.0.0',
    port: 9093
  }
});
EOF
echo -e "   ${GREEN}✓${NC} Configured for standalone Node.js"

# Install dependencies
echo -e "${CYAN}6. Installing dependencies...${NC}"
cd "$INSTALL_DIR"
pnpm remove @astrojs/vercel 2>/dev/null || true
pnpm add @astrojs/node
pnpm install
echo -e "   ${GREEN}✓${NC} Dependencies installed"

# Build
echo -e "${CYAN}7. Building application...${NC}"
pnpm build
echo -e "   ${GREEN}✓${NC} Build complete"

# Create systemd service
echo -e "${CYAN}8. Creating systemd service...${NC}"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Security Scanner Web UI
After=network.target

[Service]
Type=simple
User=fedlin
Group=fedlin
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/node $INSTALL_DIR/dist/server/entry.mjs
Restart=on-failure
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=$SERVICE_NAME
Environment=NODE_ENV=production
Environment=HOST=0.0.0.0
Environment=PORT=$PORT

[Install]
WantedBy=multi-user.target
EOF

# Set permissions
chown -R fedlin:fedlin "$INSTALL_DIR"

# Enable and start service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo -e "   ${GREEN}✓${NC} Service installed and started"

# Configure firewall
echo -e "${CYAN}9. Configuring firewall...${NC}"
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${PORT}/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    echo -e "   ${GREEN}✓${NC} Firewall configured"
else
    echo -e "   ${YELLOW}ℹ${NC} No firewall detected"
fi

# Verify
echo -e "${CYAN}10. Verifying deployment...${NC}"
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "   ${GREEN}✓${NC} Service is running"
else
    echo -e "   ${RED}✗${NC} Service failed to start"
    journalctl -u "$SERVICE_NAME" --no-pager -n 20
    exit 1
fi

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Deployment complete!${NC}"
echo ""
echo -e "${BOLD}Access the Security Scanner at:${NC}"
echo -e "  ${CYAN}http://vision:${PORT}${NC}"
echo -e "  ${CYAN}http://192.168.1.116:${PORT}${NC}"
echo ""
echo -e "${BOLD}Service management:${NC}"
echo -e "  ${CYAN}sudo systemctl status ${SERVICE_NAME}${NC}"
echo -e "  ${CYAN}sudo systemctl restart ${SERVICE_NAME}${NC}"
echo -e "  ${CYAN}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
echo ""

