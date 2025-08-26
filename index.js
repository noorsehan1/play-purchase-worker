export default {
  async fetch(request, env) {
    if (request.method === "POST") {
      try {
        const { productId, purchaseToken } = await request.json();
        const packageName = "com.chatmoz.app";

        // Ambil secrets dari environment
        const GOOGLE_CLIENT_EMAIL = env.GOOGLE_CLIENT_EMAIL;
        const GOOGLE_PRIVATE_KEY = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");

        // Ambil access token dari Google
        const accessToken = await getGoogleAccessToken(GOOGLE_CLIENT_EMAIL, GOOGLE_PRIVATE_KEY);

        const apiUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
        const res = await fetch(apiUrl, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });
        const data = await res.json();

        if (data.purchaseState === 0) {
          return new Response("VALID", { status: 200 });
        } else {
          return new Response("INVALID", { status: 200 });
        }

      } catch (err) {
        return new Response("INVALID", { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function getGoogleAccessToken(clientEmail, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const base64url = (obj) =>
    btoa(JSON.stringify(obj)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

  const unsignedJwt = `${base64url(header)}.${base64url(claim)}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    str2ab(privateKey),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsignedJwt)
  );

  const signedJwt = `${unsignedJwt}.${btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")}`;

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${signedJwt}`,
  });

  const tokenData = await tokenRes.json();
  return tokenData.access_token;
}

function str2ab(pem) {
  const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const bstr = atob(b64);
  const buf = new ArrayBuffer(bstr.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bstr.length; i++) view[i] = bstr.charCodeAt(i);
  return buf;
}
