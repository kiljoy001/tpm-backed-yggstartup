#!/bin/bash
# Setup TPM-secured Yggdrasil as systemd service

# Copy startup script
sudo cp yggdrasil-tpm-startup.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/yggdrasil-tmp-startup.sh

# Backup original service
sudo cp /lib/systemd/system/yggdrasil.service /lib/systemd/system/yggdrasil.service.backup

# Update service file
sudo sed -i 's|ExecStart=/usr/bin/yggdrasil.*|ExecStart=/usr/local/bin/yggdrasil-tpm-startup.sh|' /lib/systemd/system/yggdrasil.service

# Add writable path for tmp metadata
sudo sed -i '/ReadWritePaths=/s|$| /var/run/yggdrasil/tpmdata/|' /lib/systemd/system/yggdrasil.service

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart yggdrasil

echo "TPM-secured Yggdrasil service configured"
