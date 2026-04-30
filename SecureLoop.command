#!/bin/zsh
set -e

cd "$(dirname "$0")"

echo "Starting SecureLoop..."
echo

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is required to run SecureLoop."
  echo "Install Node.js from https://nodejs.org, then open this file again."
  echo
  read "?Press Return to close."
  exit 1
fi

if [ ! -d "node_modules" ]; then
  echo "Installing SecureLoop dependencies. This only needs to happen once."
  npm install
  echo
fi

echo "Dashboard will open at http://localhost:3334"
echo "Keep this window open while using SecureLoop."
echo

SECURELOOP_NO_AUTO_OPEN=1 npm start &
SERVER_PID=$!

for i in {1..30}; do
  if curl -fsS "http://127.0.0.1:3334/api/status" >/dev/null 2>&1; then
    /usr/bin/open "http://localhost:3334"
    echo "SecureLoop is running. Close this window or press Ctrl+C to stop it."
    echo
    wait "$SERVER_PID"
    exit $?
  fi
  sleep 0.5
done

echo "SecureLoop started, but the browser did not open automatically."
echo "Open this URL manually: http://localhost:3334"
echo
wait "$SERVER_PID"
