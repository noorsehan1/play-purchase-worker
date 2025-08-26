export default {
  async fetch(request) {
    if (request.method === "POST") {
      try {
        // Ambil JSON dari request
        const { userId, productId, purchaseToken } = await request.json();

        console.log("Request masuk:", userId, productId, purchaseToken);

        // Dummy check → nanti bisa diganti cek real Google Play API
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
