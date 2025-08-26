export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Only POST allowed", { status: 405 });
    }

    try {
      const body = await request.json();
      const { productId, purchaseToken } = body;

      if (!productId || !purchaseToken) {
        return new Response("Missing fields", { status: 400 });
      }

      // 🔐 Package name hardcode (aman)
      const packageName = "com.chatmoz.app";

      // 🔎 Panggil Google API untuk cek
      const url = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${packageName}/purchases/products/${productId}/tokens/${purchaseToken}`;

      const resp = await fetch(url, {
        headers: {
          "Authorization": `Bearer ${env.GOOGLE_PLAY_API_KEY}`, // Simpan di Secrets
          "Accept": "application/json"
        }
      });

      if (!resp.ok) {
        return new Response("INVALID", { status: 400 });
      }

      const data = await resp.json();

      // ✅ Google kasih "purchaseState": 0 → valid
      if (data.purchaseState === 0) {
        return new Response("VALID", { status: 200 });
      } else {
        return new Response("INVALID", { status: 400 });
      }
    } catch (err) {
      return new Response("ERROR: " + err.message, { status: 500 });
    }
  }
};
