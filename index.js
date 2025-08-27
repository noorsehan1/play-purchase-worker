import { SignJWT } from "jose";

export default {
  async fetch(req, env) {
    // 1. Ambil secrets dari environment
    const clientEmail = env.GOOGLE_CLIENT_EMAIL;
    let privateKey = env.GOOGLE_PRIVATE_KEY;

    // Google private key biasanya ada karakter escaped "\n" → ubah ke newline
    privateKey = privateKey.replace(/\\n/g, "\n");

    // 2. Claim JWT sesuai service account flow
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/androidpublisher", // contoh scope Play Developer API
      aud: env.GOOGLE_TOKEN_URI,
      iat: now,
      exp: now + 3600, // 1 jam
    };

    // 3. Sign JWT pakai jose
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .sign(await crypto.subtle.importKey(
        "pkcs8",
        str2ab(privateKey),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      ));

    // 4. Tukar JWT ke access_token
    const resp = await fetch(env.GOOGLE_TOKEN_URI, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
    });

    const data = await resp.json();

    return new Response(JSON.stringify(data, null, 2), {
      headers: { "Content-Type": "application/json" },
    });
  },
};

// Helper: convert string → ArrayBuffer
function str2ab(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const raw = atob(b64);
  const buf = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < raw.length; i++) {
    view[i] = raw.charCodeAt(i);
  }
  return buf;
}
