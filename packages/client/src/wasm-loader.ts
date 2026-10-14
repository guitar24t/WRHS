// The build stores the RDP client's WebAssembly gzip-compressed and base64
// encoded inside the page (about a third of its raw size). This turns it back
// into bytes for WebAssembly.instantiate. No network access is involved, so
// the page's Content-Security-Policy keeps connect-src limited to the relay.

export async function inflateWasm(base64: string): Promise<ArrayBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Response(stream).arrayBuffer();
}
