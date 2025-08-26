import * as jose from "jose";

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Only POST allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const { productId, purchaseToken } = body;

      if (!productId || !purchaseToken) {
        return new Response("Missing fields", { status: 400 });
      }

      // 🔑 Ambil service account dari Secrets
      const serviceAccount = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT);

      // 1️⃣ Buat JWT untuk OAuth2
      const iat = Math.floor(Date.now() / 1000);
      const exp = iat + 3600;
      const payload = {
        iss: serviceAccount.client_email,
        scope: "https://www.googleapis.com/auth/androidpublisher",
        aud: "https://oauth2.googleapis.com/token",
        exp,
        iat
      };

      const privateKey = await jose.importPKCS8(serviceAccount.private_key, "RS256");
      const jwt = await new jose.SignJWT(payload)
        .setProtectedHeader({ alg: "RS256" })
        .setIssuedAt(iat)
        .setExpirationTime(exp)
        .sign(privateKey);

      // 2️⃣ Tukar JWT jadi Access Token
      const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
          assertion: jwt
        })
      });

      const tokenData = await tokenResp.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) {
        return new Response("ERROR: Cannot get access token", { status: 500 });
      }

      // 3️⃣ Verifikasi pembelian ke Google API
      const packageName = "com.chatmoz.app"; // ⚠️ pastikan sama persis dengan Play Console
      const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;

      const resp = await fetch(url, {
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Accept": "application/json"
        }
      });

      const data = await resp.json();

      // ✅ purchaseState = 0 artinya sukses
      if (data.purchaseState === 0) {
        return new Response("VALID", { status: 200 });
      } else {
        return new Response("INVALID", { status: 400 });
      }
    } catch (err) {
      return new Response("ERROR: " + err.message, { status: 500 });
    }
  }
};
