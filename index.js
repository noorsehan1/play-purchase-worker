const PACKAGE_NAME = PACKAGE_NAME; // from wrangler vars

export default {
  async fetch(req) {
    if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

    try {
      const body = await req.json();
      const { productId, purchaseToken } = body;

      if (!productId || !purchaseToken) return new Response("INVALID", { status: 400 });

      // === Build JWT manually for Google OAuth2 ===
      const now = Math.floor(Date.now() / 1000);
      const header = { alg: "RS256", typ: "JWT" };
      const payload = {
        iss: GOOGLE_CLIENT_EMAIL,
        scope: "https://www.googleapis.com/auth/androidpublisher",
        aud: "https://oauth2.googleapis.com/token",
        exp: now + 3600,
        iat: now
      };

      const base64url = (str) => btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

      const unsignedJWT = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;

      const cryptoKey = await crypto.subtle.importKey(
        "pkcs8",
        Uint8Array.from(atob(GOOGLE_PRIVATE_KEY.replace(/\\n/g, "")), c => c.charCodeAt(0)),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"]
      );

      const signature = await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        new TextEncoder().encode(unsignedJWT)
      );

      const jwt = `${unsignedJWT}.${Buffer.from(signature).toString("base64url")}`;

      // === Fetch access token from Google ===
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
      });
      const tokenJson = await tokenRes.json();
      const accessToken = tokenJson.access_token;

      // === Verify purchase ===
      const res = await fetch(
        `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PACKAGE_NAME}/purchases/products/${productId}/tokens/${purchaseToken}`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      const data = await res.json();

      if (data.purchaseState === 0) return new Response("VALID", { status: 200 });
      return new Response("INVALID", { status: 200 });

    } catch (err) {
      return new Response("INVALID", { status: 500 });
    }
  }
};
