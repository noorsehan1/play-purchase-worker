export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const packageName = url.searchParams.get("packageName");
    const productId = url.searchParams.get("productId");
    const purchaseToken = url.searchParams.get("purchaseToken");

    if (!packageName || !productId || !purchaseToken) {
      return new Response(
        JSON.stringify({ error: "Harus kirim ?packageName=&productId=&purchaseToken=" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      );
    }

    // ===== JWT HEADER =====
    const jwtHeader = {
      alg: "RS256",
      typ: "JWT",
    };

    // ===== JWT CLAIM SET =====
    const jwtClaimSet = {
      iss: env.GOOGLE_CLIENT_EMAIL,
      scope: "https://www.googleapis.com/auth/androidpublisher",
      aud: env.GOOGLE_TOKEN_URI,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 jam
      iat: Math.floor(Date.now() / 1000),
    };

    // helper base64
    function base64url(source) {
      let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
      return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function str2ab(str) {
      const buf = new ArrayBuffer(str.length);
      const bufView = new Uint8Array(buf);
      for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i);
      }
      return buf;
    }

    // buat kunci
    const encoder = new TextEncoder();
    const keyData = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      str2ab(keyData),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    // encode header & claim
    const encHeader = base64url(encoder.encode(JSON.stringify(jwtHeader)));
    const encClaim = base64url(encoder.encode(JSON.stringify(jwtClaimSet)));
    const signatureInput = encoder.encode(`${encHeader}.${encClaim}`);

    // sign JWT
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, signatureInput);
    const encSignature = base64url(signature);
    const jwt = `${encHeader}.${encClaim}.${encSignature}`;

    // ===== EXCHANGE JWT → ACCESS TOKEN =====
    const tokenRes = await fetch(env.GOOGLE_TOKEN_URI, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return new Response(JSON.stringify({ error: "Gagal ambil access_token", detail: tokenData }, null, 2), {
        headers: { "Content-Type": "application/json" },
        status: 500,
      });
    }

    // ===== VERIFY PURCHASE =====
    const verifyUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
    const verifyRes = await fetch(verifyUrl, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const purchaseData = await verifyRes.json();

    return new Response(JSON.stringify(purchaseData, null, 2), {
      headers: { "Content-Type": "application/json" },
    });
  },
};
