=/**
 * play-purchase-worker
 * Cloudflare Worker untuk verifikasi Google Play purchase
 */

export default {
  async fetch(request, env) {
    try {
      // Hanya menerima POST
      if (request.method !== "POST") {
        return new Response("Request method not allowed", { status: 405 });
      }

      const body = await request.json();
      const { productId, purchaseToken } = body;

      if (!productId || !purchaseToken) {
        return new Response("Missing productId or purchaseToken", { status: 400 });
      }

      // Membuat JWT untuk autentikasi Google Service Account
      const jwt = await createJWT(env.GOOGLE_CLIENT_EMAIL, env.GOOGLE_PRIVATE_KEY);

      // Ambil akses token dari Google OAuth2
      const accessToken = await getAccessToken(jwt);

      // Verifikasi purchase ke Google Play API
      const verifyUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${env.PACKAGE_NAME}/purchases/products/${productId}/tokens/${purchaseToken}`;
      const response = await fetch(verifyUrl, {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/json",
        },
      });

      const result = await response.json();

      // Jika purchase valid dan status purchaseOK (purchaseState === 0)
      if (result && result.purchaseState === 0) {
        return new Response("VALID", { status: 200 });
      } else {
        return new Response("INVALID", { status: 200 });
      }

    } catch (err) {
      console.error("Error verifying purchase:", err);
      return new Response("INVALID", { status: 200 });
    }
  },
};

// ================= Helper functions =================
async function createJWT(clientEmail, privateKey) {
  const header = {
    alg: "RS256",
    typ: "JWT",
  };

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const base64Encode = (obj) =>
    btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const header64 = base64Encode(header);
  const payload64 = base64Encode(payload);
  const signatureBase = `${header64}.${payload64}`;

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    decodeBase64(privateKey),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signatureBase)
  );

  const signature64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${signatureBase}.${signature64}`;
}

async function getAccessToken(jwt) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  const data = await res.json();
  return data.access_token;
}

function decodeBase64(str) {
  // Hilangkan header/footer -----BEGIN/END PRIVATE KEY----- dan newline
  const clean = str
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\n/g, "");
  return Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
}
