import jwt from '@tsndr/cloudflare-worker-jwt';

// Ambil dari wrangler.toml
const GOOGLE_CLIENT_EMAIL = GOOGLE_CLIENT_EMAIL;
const GOOGLE_PRIVATE_KEY = GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'); // ubah \n menjadi newline
const PACKAGE_NAME = PACKAGE_NAME;

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405 });
    }

    try {
      const data = await request.json();
      const { productId, purchaseToken } = data;

      if (!productId || !purchaseToken) {
        return new Response('INVALID', { status: 400 });
      }

      // Buat JWT untuk Google OAuth
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

      // Ambil access_token dari Google
      const resToken = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${token}`
      });
      const tokenJson = await resToken.json();
      const accessToken = tokenJson.access_token;

      if (!accessToken) {
        return new Response('INVALID', { status: 401 });
      }

      // Verifikasi purchase token ke Google Play API
      const verifyRes = await fetch(
        `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PACKAGE_NAME}/purchases/products/${productId}/tokens/${purchaseToken}`,
        {
          headers: { Authorization: `Bearer ${accessToken}` }
        }
      );

      if (verifyRes.status === 200) {
        return new Response('VALID', { status: 200 });
      } else {
        return new Response('INVALID', { status: 400 });
      }
    } catch (err) {
      return new Response('INVALID', { status: 500 });
    }
  }
};
