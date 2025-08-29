export default {
  async fetch(request, env) {

    const clientEmail = env.GOOGLE_CLIENT_EMAIL;
    const privateKey = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g,"\n");
    const tokenUri = env.GOOGLE_TOKEN_URI;

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), { status: 405 });
    }

    let packageName, productId, purchaseToken;
    try {
      const body = await request.json();
      packageName = body.packageName;
      productId = body.productId;
      purchaseToken = body.purchaseToken;
    } catch {
      return new Response(JSON.stringify({ error: "Body JSON tidak valid" }), { status: 400 });
    }

    if (!packageName || !productId || !purchaseToken) {
      return new Response(JSON.stringify({ error: "packageName, productId, purchaseToken wajib" }), { status: 400 });
    }

    function base64url(source) {
      let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
      return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    const keyLines = privateKey.replace("-----BEGIN PRIVATE KEY-----","")
      .replace("-----END PRIVATE KEY-----","")
      .replace(/\n/g,"");
    const keyBytes = Uint8Array.from(atob(keyLines), c=>c.charCodeAt(0));

    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      keyBytes.buffer,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const header = { alg:"RS256", typ:"JWT" };
    const now = Math.floor(Date.now()/1000);
    const claim = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/androidpublisher",
      aud: tokenUri,
      iat: now,
      exp: now + 3600
    };

    const encoder = new TextEncoder();
    const encHeader = base64url(encoder.encode(JSON.stringify(header)));
    const encClaim = base64url(encoder.encode(JSON.stringify(claim)));
    const sigInput = encoder.encode(`${encHeader}.${encClaim}`);
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, sigInput);
    const encSig = base64url(signature);
    const jwt = `${encHeader}.${encClaim}.${encSig}`;

    const tokenRes = await fetch(tokenUri, {
      method:"POST",
      headers:{ "Content-Type":"application/x-www-form-urlencoded" },
      body:`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
    });
    const tokenData = await tokenRes.json();
    if(!tokenData.access_token) return new Response(JSON.stringify({error:"Gagal ambil access_token"}), {status:500});

    const verifyUrl = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;
    const verifyRes = await fetch(verifyUrl, { headers:{ Authorization:`Bearer ${tokenData.access_token}` }});
    const purchaseData = await verifyRes.json();

    return new Response(JSON.stringify({ purchaseData }), { headers:{ "Content-Type":"application/json" } });
  }
};
