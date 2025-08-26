export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    try {
      const { userId, productId, purchaseToken } = await request.json();

      // 🔑 Data environment (disimpan di Cloudflare Secrets)
      const serviceAccount = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT); // service account JSON
      const packageName = env.ANDROID_PACKAGE; // com.your.app
      const firebaseUrl = env.FIREBASE_URL;   // https://xxx.firebaseio.com
      const firebaseSecret = env.FIREBASE_SECRET; // kalau pakai DB secret

      // 1️⃣ Ambil access token pakai service account
      const jwt = await generateJWT(serviceAccount);
      const accessToken = await getAccessToken(jwt);

      // 2️⃣ Verifikasi pembelian ke Google Play
      const playUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;

      const playRes = await fetch(playUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const playData = await playRes.json();

      if (playData.purchaseState === 0) {
        // ✅ Pembelian valid → update Firebase
        await fetch(`${firebaseUrl}/users/${userId}/isVIP.json?auth=${firebaseSecret}`, {
          method: "PUT",
          body: JSON.stringify(true),
        });

        return new Response("VALID", { status: 200 });
      } else {
        return new Response("INVALID", { status: 200 });
      }
    } catch (err) {
      return new Response("ERROR: " + err.message, { status: 500 });
    }
  },
};

// ------------------ Helper Functions ------------------

// Generate JWT pakai service account
async function generateJWT(sa) {
  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/androidpublisher",
    aud: sa.token_uri,
    exp: now + 3600,
    iat: now,
  };

  const enc = (obj) => btoa(JSON.stringify(obj)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const headerEnc = enc(header);
  const claimEnc = enc(claim);
  const toSign = `${headerEnc}.${claimEnc}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    str2ab(atob(sa.private_key.split("-----")[2].replace(/\n/g, ""))),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(toSign));
  const sigEnc = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

  return `${toSign}.${sigEnc}`;
}

// Tukar JWT dengan Access Token
async function getAccessToken(jwt) {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  const data = await res.json();
  return data.access_token;
}

// String ke ArrayBuffer
function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
