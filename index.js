export default {
  async fetch(request, env) {
    try {
      if (request.method !== "POST") {
        return new Response(JSON.stringify({ error: "Method not allowed" }), {
          status: 405,
          headers: { "Content-Type": "application/json" },
        });
      }

      const body = await request.json();
      const { productId, purchaseToken } = body;
      const packageName = body.packageName || "com.chatmoz.app";

      if (!productId || !purchaseToken) {
        return new Response(JSON.stringify({ error: "Missing parameters" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }

      // ===== Step 1: Buat JWT =====
      const jwtHeader = { alg: "RS256", typ: "JWT" };
      const now = Math.floor(Date.now() / 1000);
      const jwtClaimSet = {
        iss: env.GOOGLE_CLIENT_EMAIL,
        scope: "https://www.googleapis.com/auth/androidpublisher",
        aud: env.GOOGLE_TOKEN_URI,
        exp: now + 3600,
        iat: now,
      };

      function base64url(source) {
        let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
        return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      }

      const keyPem = env.GOOGLE_PRIVATE_KEY.includes("\\n")
        ? env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n")
        : env.GOOGLE_PRIVATE_KEY;

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

      const encoder = new TextEncoder();
      const encHeader = base64url(encoder.encode(JSON.stringify(jwtHeader)));
      const encClaim = base64url(encoder.encode(JSON.stringify(jwtClaimSet)));
      const toSign = encoder.encode(`${encHeader}.${encClaim}`);

      const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, toSign);
      const encSignature = base64url(signature);
      const jwt = `${encHeader}.${encClaim}.${encSignature}`;

      // ===== Step 2: Request Access Token =====
      const tokenRes = await fetch(env.GOOGLE_TOKEN_URI, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
      });

      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) {
        return new Response(JSON.stringify({ error: "Failed to get access token", details: tokenData }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }

      const accessToken = tokenData.access_token;

      // ===== Step 3: Verifikasi pembelian ke Google Play API =====
      const verifyUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;

      const verifyRes = await fetch(verifyUrl, {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      const verifyData = await verifyRes.json();

      // ===== Step 4: Return hasil verifikasi =====
      return new Response(JSON.stringify(verifyData, null, 2), {
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
