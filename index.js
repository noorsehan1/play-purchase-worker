import { google } from "googleapis";

const PACKAGE_NAME = "com.chatmoz.app";

const clientEmail = GOOGLE_CLIENT_EMAIL; // dari wrangler.toml
const privateKey = GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n"); // ubah escape sequence

async function verifyPurchase(productId, purchaseToken) {
  try {
    const authClient = new google.auth.JWT({
      email: clientEmail,
      key: privateKey,
      scopes: ['https://www.googleapis.com/auth/androidpublisher'],
    });

    const androidPublisher = google.androidpublisher({
      version: 'v3',
      auth: authClient
    });

    const res = await androidPublisher.purchases.products.get({
      packageName: PACKAGE_NAME,
      productId: productId,
      token: purchaseToken,
    });

    if (res.data && res.data.purchaseState === 0) { // 0 = purchased
      return "VALID";
    } else {
      return "INVALID";
    }
  } catch (err) {
    console.error("Verification error:", err);
    return "INVALID";
  }
}

export default {
  async fetch(request) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const productId = body.productId;
      const purchaseToken = body.purchaseToken;

      if (!productId || !purchaseToken) {
        return new Response("Missing parameters", { status: 400 });
      }

      const result = await verifyPurchase(productId, purchaseToken);
      return new Response(result, { status: 200 });
    } catch (err) {
      return new Response("Invalid request", { status: 400 });
    }
  }
};
