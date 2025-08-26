export default {
  async fetch(request, env) {
    try {
      if (request.method !== "POST") {
        console.log("Method not allowed:", request.method);
        return new Response("Method Not Allowed", { status: 405 });
      }

      const body = await request.json();
      const { productId, purchaseToken } = body;

      console.log("Incoming request:", body);

      if (!productId || !purchaseToken) {
        console.log("Missing productId or purchaseToken");
        return new Response("INVALID", { status: 400 });
      }

      // Ganti dengan package name aplikasi kamu
      const packageName = "com.chatmoz.app"; 

      const accessToken = await getGoogleAccessToken(env);
      console.log("Access token retrieved:", accessToken ? "YES" : "NO");

      const apiUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
      console.log("Calling Google API URL:", apiUrl);

      const res = await fetch(apiUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      const data = await res.json();
      console.log("Google API response:", JSON.stringify(data));

      if (data.purchaseState === 0) {
        console.log("Purchase valid");
        return new Response("VALID", { status: 200 });
      } else {
        console.log("Purchase invalid");
        return new Response("INVALID", { status: 200 });
      }
    } catch (err) {
      console.log("Error in Worker:", err);
      return new Response("INVALID", { status: 500 });
    }
  },
};

// ================= Helper: Ambil Google Access Token =================
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
  console.log("Access token response:", JSON.stringify(tokenData));
  return tokenData.access_token;
}

// ================= Helper: Convert PEM -> ArrayBuffer =================
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
