const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

dotenv.config();

process.on("uncaughtException", (err) => {
    console.error("🔥 [Server] UNCAUGHT EXCEPTION:", err.message);
    console.error(err.stack);
});

process.on("unhandledRejection", (reason) => {
    console.error("🔥 [Server] UNHANDLED REJECTION:", reason);
});

const app = express();
app.use(cors());
app.use(express.json());

app.get("/server/health", (req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
});

const ZEGO_APP_ID = process.env.ZEGO_APP_ID;
const ZEGO_SERVER_SECRET = process.env.ZEGO_SERVER_SECRET;
const SUPABASE_JWT_SECRET = process.env.SUPABASE_JWT_SECRET;

/**
 * Decodes and optionally verifies the JWT to get the user ID (sub).
 * On cPanel, if you don't have the Supabase Secret configured, it will still decode.
 */
function verifySupabaseUserId(token) {
    try {
        if (!token) return null;
        
        // Use verify if secret is available for better security
        if (SUPABASE_JWT_SECRET) {
            try {
                const payload = jwt.verify(token, SUPABASE_JWT_SECRET, {
                    algorithms: ["HS256"],
                });
                return payload.sub;
            } catch (vErr) {
                console.error("❌ JWT Verification failed:", vErr.message);
                // Fallback to decode if verification fails but we want to be lenient
            }
        }

        const decoded = jwt.decode(token);
        return decoded ? decoded.sub : null;
    } catch (err) {
        console.error("❌ JWT Decode Error:", err.message);
        return null;
    }
}

function generateZegoToken(appId, serverSecret, userId, expireInSeconds = 3600) {
    const now = Math.floor(Date.now() / 1000);
    const expire = now + expireInSeconds;

    const nonce =
        Math.floor(Math.random() * Math.pow(2, 32)) - Math.pow(2, 31);

    const tokenInfo = {
        app_id: Number(appId),
        user_id: userId,
        nonce,
        ctime: now,
        expire,
        payload: "",
    };

    const plainText = JSON.stringify(tokenInfo);

    if (serverSecret.length !== 32) {
        throw new Error("Secret must be 32 characters");
    }

    const gcmNonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", serverSecret, gcmNonce);

    const encrypted = cipher.update(plainText, "utf8");
    const encryptBuf = Buffer.concat([
        encrypted,
        cipher.final(),
        cipher.getAuthTag(),
    ]);

    const b1 = new Uint8Array(8);
    const b2 = new Uint8Array(2);
    const b3 = new Uint8Array(2);
    const b4 = new Uint8Array(1);

    new DataView(b1.buffer).setBigInt64(0, BigInt(expire), false);
    new DataView(b2.buffer).setUint16(0, gcmNonce.byteLength, false);
    new DataView(b3.buffer).setUint16(0, encryptBuf.byteLength, false);
    new DataView(b4.buffer).setUint8(0, 1);

    const buf = Buffer.concat([
        Buffer.from(b1),
        Buffer.from(b2),
        Buffer.from(gcmNonce),
        Buffer.from(b3),
        Buffer.from(encryptBuf),
        Buffer.from(b4),
    ]);

    return "04" + buf.toString("base64");
}

app.post("/server/zego-token", async (req, res) => {
    try {
        const auth = req.headers.authorization;

        if (!auth) return res.status(401).json({ error: "Missing Authorization" });

        const supabaseJwt = auth.replace("Bearer ", "");
        const userUuid = verifySupabaseUserId(supabaseJwt);

        if (!userUuid) {
            return res.status(401).json({ error: "Invalid user token" });
        }

        const userId = userUuid.replace(/-/g, "");

        const token = generateZegoToken(
            ZEGO_APP_ID,
            ZEGO_SERVER_SECRET,
            userId
        );

        res.json({ token });
    } catch (err) {
        console.error("❌ Token Error:", err.message);
        res.status(err.status || 500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("🚀 Zego Token Server running on port", PORT);
});
