export default {
  async fetch(request, env) {
    try {
      // header + claim JWT
      const jwtHeader = {
        alg: "RS256",
        typ: "JWT",
      };

      const jwtClaimSet = {
        iss: env.GOOGLE_CLIENT_EMAIL,
        scope: "https://www.googleapis.com/auth/playintegrity",
        aud: env.GOOGLE_TOKEN_URI,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      };

      // helper base64url
      function base64url(source) {
        let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
        return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      }

      // ambil private key, normalisasi newline
      const keyPem = env.GOOGLE_PRIVATE_KEY.includes("\\n")
        ? env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n")
        : env.GOOGLE_PRIVATE_KEY;

      // konversi PEM → ArrayBuffer
      function pemToArrayBuffer(pem) {
        const b64Lines = pem
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replace(/\s+/g, "");
        const byteStr = atob(b64Lines);
        const bytes = new Uint8Array(byteStr.length);
        for (let i = 0; i < byteStr.length; i++) {
          bytes[i] = byteStr.charCodeAt(i);
        }
        return bytes.buffer;
      }

      const cryptoKey = await crypto.subtle.importKey(
        "pkcs8",
        pemToArrayBuffer(keyPem),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      );

      // buat JWT
      const encoder = new TextEncoder();
      const encHeader = base64url(encoder.encode(JSON.stringify(jwtHeader)));
      const encClaim = base64url(encoder.encode(JSON.stringify(jwtClaimSet)));
      const toSign = encoder.encode(`${encHeader}.${encClaim}`);

      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        toSign
      );
      const encSignature = base64url(signature);
      const jwt = `${encHeader}.${encClaim}.${encSignature}`;

      // minta access token
      const res = await fetch(env.GOOGLE_TOKEN_URI, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
      });

      const data = await res.json();
      return new Response(JSON.stringify(data, null, 2), {
        headers: { "Content-Type": "application/json" },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  },
};
