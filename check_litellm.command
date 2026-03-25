#!/bin/bash
# Double-click this file on macOS to run the checker in Terminal.
# If blocked by Gatekeeper: right-click → Open → Open

cd "$(dirname "$0")"
bash check_litellm.sh
echo ""
echo "Press any key to close..."
read -n 1
