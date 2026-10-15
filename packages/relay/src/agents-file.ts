// The relay's list of agents allowed to register: a JSON object mapping each
// agent id to the SHA-256 (hex) of that agent's relay token, as printed by
// `wrhs-agent registration`. Keys starting with "_" are comments.

export function parseAgentsFile(json: string, file = 'the agents file'): Map<string, Buffer> {
  const raw = JSON.parse(json) as unknown;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${file} must be a JSON object: {"<agent id>": "<sha256 of its relay token>"}`);
  }
  const map = new Map<string, Buffer>();
  for (const [id, hash] of Object.entries(raw as Record<string, unknown>)) {
    if (id.startsWith('_')) continue;
    if (!/^[0-9a-f]{32}$/.test(id) || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash)) {
      throw new Error(`bad entry for ${id} in ${file}: expected "<32 hex agent id>": "<64 hex token hash>", as printed by wrhs-agent registration`);
    }
    map.set(id, Buffer.from(hash, 'hex'));
  }
  return map;
}
