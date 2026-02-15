import express from "express";
import crypto from "crypto";
import cors from "cors";
import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import dotenv from "dotenv";

dotenv.config();

process.on('uncaughtException', (err) => {
    console.error('🔥 [Server] UNCAUGHT EXCEPTION:', err.message);
    console.error(err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 [Server] UNHANDLED REJECTION:', reason);
});

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
});

const ZEGO_APP_ID = process.env.ZEGO_APP_ID;
const ZEGO_SERVER_SECRET = process.env.ZEGO_SERVER_SECRET;
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL || "https://rpequkoxeqcaqfhtygwd.supabase.co";

// JWKS client for fetching Supabase's public keys (used for ES256 tokens)
const jwks = jwksClient({
    jwksUri: `${SUPABASE_URL}/auth/v1/.well-known/jwks.json`,
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 600000, // 10 minutes
});

// Helper: get the signing key from JWKS endpoint
function getJwksKey(header, callback) {
    console.log("🔑 [Server] Fetching signing key for kid:", header.kid);
    jwks.getSigningKey(header.kid, (err, key) => {
        if (err) {
            console.error("❌ [Server] JWKS error:", err.message);
            return callback(err);
        }
        if (!key) {
            console.error("❌ [Server] No key found for kid:", header.kid);
            return callback(new Error("No key found"));
        }
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

// Verify Supabase JWT – supports both ES256 (JWKS) and HS256 (shared secret)
function verifySupabaseJwt(token) {
    return new Promise((resolve, reject) => {
        const decoded = jwt.decode(token, { complete: true });
        if (!decoded) return reject(new Error("Invalid JWT format"));

        const alg = decoded.header.alg;
        console.log("🔍 JWT Header:", JSON.stringify(decoded.header));

        if (alg === "ES256") {
            // ES256: verify with public key from JWKS endpoint
            jwt.verify(token, getJwksKey, { algorithms: ["ES256"] }, (err, payload) => {
                if (err) return reject(err);
                resolve(payload);
            });
        } else {
            // HS256 fallback: verify with shared secret
            try {
                const payload = jwt.verify(token, SUPABASE_JWT_SECRET, { algorithms: ["HS256"] });
                resolve(payload);
            } catch (err) {
                reject(err);
            }
        }
    });
}

function generateZegoToken(appId, serverSecret, userId, expireInSeconds = 3600) {
    const now = Math.floor(Date.now() / 1000);
    const expire = now + expireInSeconds;
    // Official Zego nonce: random int32 (including negatives)
    const nonce = Math.floor(Math.random() * (Math.pow(2, 32))) - Math.pow(2, 31);

    const tokenInfo = {
        app_id: Number(appId),
        user_id: userId,
        nonce,
        ctime: now,
        expire,
        payload: ""
    };

    const plainText = JSON.stringify(tokenInfo);

    // Official Zego uses the 32-char hex secret as raw string key for AES-256-GCM
    // (NOT hex-decoded — the 32-byte string IS the key)
    if (serverSecret.length !== 32) {
        throw new Error(`Secret must be a 32 character string. Got ${serverSecret.length} chars.`);
    }

    // AES-256-GCM with 12-byte random nonce (matches official zegoServerAssistant.js)
    const gcmNonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', serverSecret, gcmNonce);
    cipher.setAutoPadding(true);

    const encrypted = cipher.update(plainText, 'utf8');
    const encryptBuf = Buffer.concat([encrypted, cipher.final(), cipher.getAuthTag()]);

    console.log(`[Zego] AppID: ${appId}, UserID: ${userId}`);

    // Token04 binary format (official):
    //   expire_time      (8 bytes, BigInt64BE)
    //   nonce_length     (2 bytes, Uint16BE)
    //   nonce            (12 bytes)
    //   ciphertext_length (2 bytes, Uint16BE)
    //   ciphertext       (N bytes, includes auth tag)
    //   mode             (1 byte, 1 = GCM)
    const b1 = new Uint8Array(8);
    const b2 = new Uint8Array(2);
    const b3 = new Uint8Array(2);
    const b4 = new Uint8Array(1);

    new DataView(b1.buffer).setBigInt64(0, BigInt(expire), false);
    new DataView(b2.buffer).setUint16(0, gcmNonce.byteLength, false);
    new DataView(b3.buffer).setUint16(0, encryptBuf.byteLength, false);
    new DataView(b4.buffer).setUint8(0, 1); // 1 = GCM mode

    const buf = Buffer.concat([
        Buffer.from(b1),
        Buffer.from(b2),
        Buffer.from(gcmNonce),
        Buffer.from(b3),
        Buffer.from(encryptBuf),
        Buffer.from(b4),
    ]);

    return "04" + Buffer.from(new DataView(Uint8Array.from(buf).buffer).buffer).toString('base64');
}


app.post("/zego-token", async (req, res) => {
    console.log("📩 [Server] Received token request");
    try {
        const auth = req.headers.authorization;
        if (!auth) return res.status(401).json({ error: "Missing Authorization" });

        const supabaseJwt = auth.replace("Bearer ", "");

        // Verify Supabase JWT (supports both ES256 and HS256)
        const decoded = await verifySupabaseJwt(supabaseJwt);
        console.log("✅ JWT verified successfully for user:", decoded.sub);

        const userId = decoded.sub.replace(/-/g, ""); // same as Flutter

        const token = generateZegoToken(
            ZEGO_APP_ID,
            ZEGO_SERVER_SECRET,
            userId
        );

        return res.json({ token });

    } catch (err) {
        console.error("❌ Token Error:", err.message);
        return res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Zego Token Server running on port ${PORT}`);
    console.log(`🔗 JWKS endpoint: ${SUPABASE_URL}/auth/v1/.well-known/jwks.json`);
});
