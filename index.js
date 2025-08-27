export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    let packageName, productId, purchaseToken;

    try {
      const body = await request.json();
      packageName = body.packageName;
      productId = body.productId;
      purchaseToken = body.purchaseToken;
    } catch (err) {
      return new Response(JSON.stringify({ error: "Body JSON tidak valid" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (!packageName || !productId || !purchaseToken) {
      return new Response(
        JSON.stringify({ error: "Harus kirim packageName, productId, dan purchaseToken di body JSON" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // ===== helper & JWT code tetap sama =====
    function base64url(source) {
      let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
      return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    const keyPem = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");
    const keyLines = keyPem.replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replace(/\n/g, "");
    const keyBytes = Uint8Array.from(atob(keyLines), c => c.charCodeAt(0));

    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      keyBytes.buffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const jwtHeader = { alg: "RS256", typ: "JWT" };
    const jwtClaimSet = {
      iss: env.GOOGLE_CLIENT_EMAIL,
      scope: "https://www.googleapis.com/auth/androidpublisher",
      aud: env.GOOGLE_TOKEN_URI,
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };

    const encoder = new TextEncoder();
    const encHeader = base64url(encoder.encode(JSON.stringify(jwtHeader)));
    const encClaim = base64url(encoder.encode(JSON.stringify(jwtClaimSet)));
    const signatureInput = encoder.encode(`${encHeader}.${encClaim}`);
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, signatureInput);
    const encSignature = base64url(signature);
    const jwt = `${encHeader}.${encClaim}.${encSignature}`;

    const tokenRes = await fetch(env.GOOGLE_TOKEN_URI, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return new Response(JSON.stringify({ error: "Gagal ambil access_token", detail: tokenData }, null, 2), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 500,
      });
    }

    const verifyUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
    const verifyRes = await fetch(verifyUrl, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const purchaseData = await verifyRes.json();

    return new Response(JSON.stringify(purchaseData, null, 2), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  },
};
