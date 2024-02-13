/**
 *
 * @param length The length of the random string
 * @return A random string of the given length
 */
export function generateRandomString(length: number): string {
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

// See https://thewoods.blog/base64url/
export function base64urlDecode(encoded: string): ArrayBuffer {
  const m = encoded.length % 4 || 4;
  const b64 = encoded
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(encoded.length + 4 - m, "=");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

/**
 *
 * @param str Some string to encode
 * @return the base64url encoded string
 */
export function base64urlEncode(buffer: ArrayBuffer): string {
  const str = String.fromCodePoint(...new Uint8Array(buffer));
  const b64 = btoa(str);
  const urlb64 = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return urlb64;
}

/**
 *
 * @param plain Some string to hash
 * @return the hash of the input string
 */
export async function sha256(plain: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const digest = await window.crypto.subtle.digest("SHA-256", data);
  return digest;
}
