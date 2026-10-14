// Assembles dist/windows: everything needed to install the agent on a
// Windows PC (with Node.js 22.18+). Run via `npm run package:windows`.

import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../..');
const out = join(root, 'dist/windows');
mkdirSync(out, { recursive: true });

for (const f of ['wrhs-agent.mjs', 'launcher.template.html']) copyFileSync(join(root, 'dist/agent', f), join(out, f));
for (const f of ['install.ps1', 'uninstall.ps1']) copyFileSync(join(here, f), join(out, f));
writeFileSync(
  join(out, 'README.txt'),
  `WRHS agent for Windows
======================

Serves this PC's desktop to the WRHS browser client, like Remote Desktop:
you get your own session and the PC's screen locks while you are connected.

Requirements: Windows Pro, Enterprise, Education or Server, and Node.js 22.18
or later installed for all users (https://nodejs.org or
"winget install OpenJS.NodeJS.LTS").

Install (PowerShell as administrator, in this folder):

  powershell -ExecutionPolicy Bypass -File .\\install.ps1 -RelayUrl https://relay.example.com -User alice

Remove:

  powershell -ExecutionPolicy Bypass -File .\\uninstall.ps1

Details: docs/WINDOWS.md in the WRHS repository.
`.replace(/\n/g, '\r\n'),
);
console.log(`Windows package: ${out}`);
