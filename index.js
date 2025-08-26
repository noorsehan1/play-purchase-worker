export default {
  async fetch(request, env) {
    if (request.method === "POST") {
      try {
        const { productId, purchaseToken } = await request.json();

        if (!productId || !purchaseToken) {
          return new Response(
            JSON.stringify({ error: "Missing productId or purchaseToken" }),
            { status: 400 }
          );
        }

        const packageName = "com.chatmoz.app"; // ganti sesuai package app kamu
        const accessToken = await getGoogleAccessToken(env);

        const apiUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
        const res = await fetch(apiUrl, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });

        const data = await res.json();

        // Logging untuk debugging
        console.log("Google API response:", data);

        if (data.error) {
          return new Response(
            JSON.stringify({ valid: false, reason: data.error }),
            { status: 200 }
          );
        }

        // purchaseState = 0 artinya valid
        if (data.purchaseState === 0) {
          return new Response(
            JSON.stringify({ valid: true, purchaseState: data.purchaseState }),
            { status: 200 }
          );
        } else {
          return new Response(
            JSON.stringify({
              valid: false,
              purchaseState: data.purchaseState,
              message: data.developerPayload || "Purchase not valid",
            }),
            { status: 200 }
          );
        }
      } catch (err) {
        console.error("Worker error:", err);
        return new Response(
          JSON.stringify({ valid: false, error: err.toString() }),
          { status: 500 }
        );
      }
    }

    return new Response("Not Found", { status: 404 });
  },
};

// Ambil Google Access Token dari Service Account
async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: env.GOOGLE_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const base64url = (obj) =>
    btoa(JSON.stringify(obj))
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const unsignedJwt = `${base64url(header)}.${base64url(claim)}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    str2ab(env.GOOGLE_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsignedJwt)
  );

  const signedJwt = `${unsignedJwt}.${btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
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

// Convert PEM Private Key -> ArrayBuffer
function str2ab(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");

  const bstr = atob(b64);
  const buf = new ArrayBuffer(bstr.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bstr.length; i++) view[i] = bstr.charCodeAt(i);
  return buf;
}
