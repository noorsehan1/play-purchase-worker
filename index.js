const PACKAGE_NAME = "com.chatmoz.app";

function base64urlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function createJWT(payload, privateKey) {
  const encoder = new TextEncoder();
  const header = { alg: 'RS256', typ: 'JWT' };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);

  const keyData = privateKey.replace('-----BEGIN PRIVATE KEY-----', '')
                            .replace('-----END PRIVATE KEY-----', '')
                            .replace(/\n/g, '');
  const keyBuffer = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    keyBuffer.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, data));
  return `${encodedHeader}.${encodedPayload}.${base64urlEncode(String.fromCharCode(...signature))}`;
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });

    try {
      const { productId, purchaseToken } = await request.json();
      if (!productId || !purchaseToken) return new Response('INVALID', { status: 200 });

      const GOOGLE_CLIENT_EMAIL = env.GOOGLE_CLIENT_EMAIL;
      const GOOGLE_PRIVATE_KEY = env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');

      const payload = {
        iss: GOOGLE_CLIENT_EMAIL,
        scope: 'https://www.googleapis.com/auth/androidpublisher',
        aud: 'https://oauth2.googleapis.com/token',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      };

      const jwt = await createJWT(payload, GOOGLE_PRIVATE_KEY);

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`
      });

      const tokenJson = await tokenRes.json();
      const accessToken = tokenJson.access_token;
      if (!accessToken) return new Response('INVALID', { status: 200 });

      const verifyRes = await fetch(
        `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PACKAGE_NAME}/purchases/products/${productId}/tokens/${purchaseToken}`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      const verifyData = await verifyRes.json();
      if (verifyRes.status === 200 && verifyData.purchaseState === 0) {
        return new Response('VALID', { status: 200 });
      } else {
        return new Response('INVALID', { status: 200 });
      }

    } catch (err) {
      console.error('Verifikasi gagal:', err);
      return new Response('INVALID', { status: 200 });
    }
  }
};
