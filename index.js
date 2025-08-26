import jwt from 'jsonwebtoken';

const GOOGLE_CLIENT_EMAIL = GLOBALS.GOOGLE_CLIENT_EMAIL;
const GOOGLE_PRIVATE_KEY = GLOBALS.GOOGLE_PRIVATE_KEY;
const PACKAGE_NAME = GLOBALS.PACKAGE_NAME;

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("Request method not allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const { productId, purchaseToken } = body;

      // 1. Buat JWT untuk access_token
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iss: GOOGLE_CLIENT_EMAIL,
        scope: "https://www.googleapis.com/auth/androidpublisher",
        aud: "https://oauth2.googleapis.com/token",
        exp: now + 3600,
        iat: now
      };

      const token = jwt.sign(payload, GOOGLE_PRIVATE_KEY, { algorithm: "RS256" });

      // 2. Request access token dari Google
      const accessTokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${token}`
      });

      const accessTokenData = await accessTokenRes.json();
      const accessToken = accessTokenData.access_token;

      // 3. Request verifikasi pembelian
      const verifyUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PACKAGE_NAME}/purchases/products/${productId}/tokens/${purchaseToken}`;
      const verifyRes = await fetch(verifyUrl, {
        headers: { "Authorization": `Bearer ${accessToken}` }
      });

      const verifyData = await verifyRes.json();

      if (verifyData && verifyData.purchaseState === 0) {
        return new Response("VALID");
      } else {
        return new Response("INVALID");
      }

    } catch (err) {
      return new Response("ERROR: " + err.message, { status: 500 });
    }
  }
}
