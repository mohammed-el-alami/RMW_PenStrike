#!/bin/bash

set -e

APP_NAME="rmwpen"
INSTALL_DIR="/opt/$APP_NAME"
BIN_PATH="/usr/local/bin/$APP_NAME"

echo "[+] Installing $APP_NAME..."

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Run this installer with sudo:"
    echo "sudo ./install.sh"
    exit 1
fi


echo "[+] Installing required system packages..."

apt update
apt install -y python3 python3-venv python3-pip


echo "[+] Creating application directory..."

mkdir -p "$INSTALL_DIR"


echo "[+] Copying application files..."

# Copy everything except venv
cp -r ./* "$INSTALL_DIR/"


echo "[+] Creating Python virtual environment..."

python3 -m venv "$INSTALL_DIR/venv"


echo "[+] Installing Python dependencies..."

"$INSTALL_DIR/venv/bin/pip" install \
    openai \
    httpx \
    reportlab \
    python-docx


echo "[+] Fixing permissions..."

chown -R "$SUDO_USER":"$SUDO_USER" "$INSTALL_DIR"


echo "[+] Creating launcher..."

cat > "$BIN_PATH" <<EOF
#!/bin/bash

APP_DIR="$INSTALL_DIR"

source "\$APP_DIR/venv/bin/activate"

python3 "\$APP_DIR/main.py" "\$@"
EOF


chmod +x "$BIN_PATH"


echo ""
echo "[+] Installation completed!"
echo ""
echo "You can now run:"
echo ""
echo "    $APP_NAME -h"
echo ""