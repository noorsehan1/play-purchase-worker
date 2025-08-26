import { google } from 'googleapis';

const clientEmail = GOOGLE_CLIENT_EMAIL;
const privateKey = GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'); // convert escaped newline

async function verifyPurchase(productId, purchaseToken) {
    try {
        const auth = new google.auth.JWT(
            clientEmail,
            null,
            privateKey,
            ['https://www.googleapis.com/auth/androidpublisher']
        );

        const androidPublisher = google.androidpublisher({
            version: 'v3',
            auth: auth
        });

        // Ganti PACKAGE_NAME sesuai project
        const res = await androidPublisher.purchases.products.get({
            packageName: PACKAGE_NAME,
            productId: productId,
            token: purchaseToken
        });

        if (res.data && res.data.purchaseState === 0) {
            return 'VALID';
        }
        return 'INVALID';
    } catch (err) {
        console.error('Error verifying purchase:', err);
        return 'INVALID';
    }
}

export default {
    async fetch(request) {
        try {
            if (request.method !== 'POST') {
                return new Response('Method Not Allowed', { status: 405 });
            }

            const body = await request.json();
            const { productId, purchaseToken } = body;

            const result = await verifyPurchase(productId, purchaseToken);
            return new Response(result, { status: 200 });
        } catch (err) {
            console.error(err);
            return new Response('INVALID', { status: 200 });
        }
    }
};
