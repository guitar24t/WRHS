#!/usr/bin/env bash
# Prepares a local, all-in-one demo: relay + agent + guacd + a throwaway
# Linux desktop (xrdp). Then: docker compose up --build, and open the
# generated launcher file in your browser.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p data
CLI=(node ../../packages/agent/src/cli.ts --config data/agent.json)

if [ ! -f data/agent.json ]; then
  "${CLI[@]}" init --relay http://relay:8080 --name "WRHS demo"
  # Inside the compose network guacd is reachable by service name.
  node -e '
    const fs = require("fs");
    const c = JSON.parse(fs.readFileSync("data/agent.json", "utf8"));
    c.guacd = { host: "guacd", port: 4822 };
    fs.writeFileSync("data/agent.json", JSON.stringify(c, null, 2) + "\n");'
  # xrdp desktop through guacd (stored demo credentials need the guacd engine).
  "${CLI[@]}" add-target --id desktop --name "Demo Linux desktop" --host desktop --engine guacd \
    --rdp-user ubuntu --rdp-password ubuntu --ignore-cert
  PASS="${DEMO_PASSWORD:-$(node -e 'console.log(require("crypto").randomBytes(12).toString("base64url"))')}"
  WRHS_PASSWORD="$PASS" "${CLI[@]}" add-user demo
  echo "$PASS" > data/demo-password.txt
fi

"${CLI[@]}" registration > data/agents.json
"${CLI[@]}" launcher --out data/wrhs-demo-launcher.html --public-url http://localhost:8080
chmod -R a+rX data
echo
echo "Demo user:     demo"
echo "Password:      $(cat data/demo-password.txt)"
echo "TOTP secret:   $(node -e 'console.log(JSON.parse(require("fs").readFileSync("data/agent.json","utf8")).users[0].totpSecret)')"
echo "               (add it to any authenticator app)"
echo
echo "Now run:  docker compose up --build"
echo "Then open deploy/demo/data/wrhs-demo-launcher.html in your browser."
