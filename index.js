import { google } from "googleapis";

export default {
  async fetch(request, env) {
    try {
      if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }

      const body = await request.json();
      const { productId, purchaseToken } = body;

      const jwtClient = new google.auth.JWT({
        email: env.GOOGLE_CLIENT_EMAIL,
        key: env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        scopes: ["https://www.googleapis.com/auth/androidpublisher"],
      });

      const publisher = google.androidpublisher({
        version: "v3",
        auth: jwtClient,
      });

      const res = await publisher.purchases.products.get({
        packageName: env.PACKAGE_NAME,
        productId,
        token: purchaseToken,
      });

      const purchase = res.data;
      if (purchase && purchase.purchaseState === 0) { // 0 = purchased
        return new Response("VALID");
      } else {
        return new Response("INVALID");
      }

    } catch (e) {
      console.error(e);
      return new Response("INVALID", { status: 500 });
    }
  }
};
