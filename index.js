import { google } from "googleapis";

// Ambil kredensial dari environment variables
const clientEmail = GOOGLE_CLIENT_EMAIL;
const privateKey = GOOGLE_PRIVATE_KEY.replace(/\\n/g, "\n"); // Pastikan newline benar

// Inisialisasi JWT client untuk Google Play API
const authClient = new google.auth.JWT({
  email: clientEmail,
  key: privateKey,
  scopes: ["https://www.googleapis.com/auth/androidpublisher"],
});

// Handler utama Worker
export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      console.log("Request method not allowed:", request.method);
      return new Response("Method Not Allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const { productId, purchaseToken } = body;

      if (!productId || !purchaseToken) {
        console.log("Missing productId or purchaseToken");
        return new Response("INVALID", { status: 400 });
      }

      await authClient.authorize();

      const androidpublisher = google.androidpublisher({
        version: "v3",
        auth: authClient,
      });

      const packageName = "com.chatmoz.app"; // Ganti dengan nama paket aplikasi Anda
      const response = await androidpublisher.purchases.products.get({
        packageName,
        productId,
        token: purchaseToken,
      });

      console.log("Purchase verification response:", response.data);

      if (response.data.purchaseState === 0) {
        return new Response("VALID", { status: 200 });
      } else {
        return new Response("INVALID", { status: 400 });
      }
    } catch (err) {
      console.error("Verification error:", err);
      return new Response("INVALID", { status: 500 });
    }
  },
};
