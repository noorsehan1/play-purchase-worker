export default {
  async fetch(request, env) {
    console.log("Incoming request:", request.url, "Method:", request.method);

    if (request.method === "POST") {
      try {
        const { productId, purchaseToken } = await request.json();
        console.log("Purchase data received:", { productId, purchaseToken });

        // 🔹 Ganti dengan package name aplikasi kamu
        const packageName = "com.chatmoz.app";

        // Ambil Google Access Token
        const accessToken = await getGoogleAccessToken(env);
        console.log("Google access token obtained");

        // Panggil Google Play Developer API
        const apiUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
        const res = await fetch(apiUrl, {
          headers: { Authorization: `Bearer ${accessToken}` },
        });

        const data = await res.json();
        console.log("Google API response:", data);

        // Tambahkan field custom 'isValid' berdasarkan purchaseState
        const responsePayload = {
          isValid: data.purchaseState === 0,
          purchaseData: data,
        };

        console.log("Response payload:", responsePayload);
        return new Response(JSON.stringify(responsePayload), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        console.error("Error verifying purchase:", err);
        return new Response(JSON.stringify({ isValid: false, error: err.toString() }), {
          status: 500,
          headers: { "Content-Type": "application/json" },
        });
      }
    }

    console.log("Request method not allowed");
    return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
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
  console.log("Access token response:", tokenData);

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
