import { google } from 'googleapis';

const PACKAGE_NAME = "com.chatmoz.app"; // sesuaikan dengan package aplikasi

// Variabel environment dari wrangler.toml
const CLIENT_EMAIL = GOOGLE_CLIENT_EMAIL;
const PRIVATE_KEY = GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'); // replace newline

/**
 * Handler Cloudflare Worker
 */
export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const { productId, purchaseToken } = body;

      if (!productId || !purchaseToken) {
        return new Response("INVALID", { status: 400 });
      }

      // Auth JWT client
      const auth = new google.auth.JWT({
        email: CLIENT_EMAIL,
        key: PRIVATE_KEY,
        scopes: ['https://www.googleapis.com/auth/androidpublisher'],
      });

      const androidpublisher = google.androidpublisher({
        version: 'v3',
        auth,
      });

      // Verifikasi token
      const res = await androidpublisher.purchases.products.get({
        packageName: PACKAGE_NAME,
        productId,
        token: purchaseToken,
      });

      // Jika purchase valid dan belum consumed
      if (res.data && res.data.purchaseState === 0) {
        return new Response("VALID", { status: 200 });
      } else {
        return new Response("INVALID", { status: 200 });
      }

    } catch (err) {
      return new Response("INVALID", { status: 500 });
    }
  }
};
