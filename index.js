export default {
  async fetch(request, env) {
    const jwtHeader = {
      alg: "RS256",
      typ: "JWT",
    };

    const jwtClaimSet = {
      iss: env.GOOGLE_CLIENT_EMAIL,
      scope: "https://www.googleapis.com/auth/playintegrity",
      aud: env.GOOGLE_TOKEN_URI,
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 jam
      iat: Math.floor(Date.now() / 1000),
    };

    // base64 encode helper
    function base64url(source) {
      let encoded = btoa(String.fromCharCode(...new Uint8Array(source)));
      return encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    // sign JWT
    const encoder = new TextEncoder();
    const keyData = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n");
    const cryptoKey = await crypto.subtle.importKey(
      "pkcs8",
      str2ab(keyData),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    function str2ab(str) {
      const buf = new ArrayBuffer(str.length);
      const bufView = new Uint8Array(buf);
      for (let i = 0; i < str.length; i++) {
        bufView[i] = str.charCodeAt(i);
      }
      return buf;
    }

    const encHeader = base64url(encoder.encode(JSON.stringify(jwtHeader)));
    const encClaim = base64url(encoder.encode(JSON.stringify(jwtClaimSet)));
    const signatureInput = encoder.encode(`${encHeader}.${encClaim}`);

    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, signatureInput);
    const encSignature = base64url(signature);

    const jwt = `${encHeader}.${encClaim}.${encSignature}`;

    // exchange JWT → access_token
    const res = await fetch(env.GOOGLE_TOKEN_URI, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    });

    const data = await res.json();

    return new Response(JSON.stringify(data, null, 2), {
      headers: { "Content-Type": "application/json" },
    });
  },
};
