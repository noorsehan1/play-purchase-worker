export default {
  async fetch(request) {
    if (request.method === "POST") {
      try {
        // Baca body JSON
        const { userId, productId, purchaseToken } = await request.json();

        // Debug log (hilangkan di production)
        console.log("Request masuk:", userId, productId, purchaseToken);

        // 👉 TODO: di sini kamu bisa tambah verifikasi beneran
        // misalnya connect ke Google Play API
        // untuk sekarang dummy cek aja:
        if (purchaseToken && purchaseToken.startsWith("gp_")) {
          return new Response("VALID", { status: 200 });
        } else {
          return new Response("INVALID", { status: 200 });
        }

      } catch (err) {
        return new Response("ERROR: " + err.message, { status: 500 });
      }
    }

    return new Response("Only POST allowed", { status: 405 });
  }
};
