import jwt from '@tsndr/cloudflare-worker-jwt';

const GOOGLE_CLIENT_EMAIL = GOOGLE_CLIENT_EMAIL;
const GOOGLE_PRIVATE_KEY = GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');
const PACKAGE_NAME = PACKAGE_NAME;

export default {
  async fetch(request) {
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const data = await request.json();
      const { productId, purchaseToken } = data;

      if (!productId || !purchaseToken) {
        return new Response('INVALID', { status: 200 });
      }

      // Buat JWT
      const token = await jwt.sign(
        {
          iss: GOOGLE_CLIENT_EMAIL,
          scope: 'https://www.googleapis.com/auth/androidpublisher',
          aud: 'https://oauth2.googleapis.com/token',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        },
        GOOGLE_PRIVATE_KEY,
        { algorithm: 'RS256' }
      );

      // Ambil access_token
      const resToken = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${token}`
      });

      const tokenJson = await resToken.json();
      const accessToken = tokenJson.access_token;

      if (!accessToken) {
        return new Response('INVALID', { status: 200 });
      }

      // Verifikasi purchase token
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
