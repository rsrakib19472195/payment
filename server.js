
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "16kb" }));

const API_KEY = process.env.TWIXO_API_KEY;
const SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!API_KEY || !SERVICE_ACCOUNT) {
  throw new Error("Required environment variables are missing");
}

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(SERVICE_ACCOUNT))
});

const db = admin.firestore();

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "TWIXO API" });
});

app.post(
  "/api/messages",
  rateLimit({
    windowMs: 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false
  }),
  async (req, res) => {
    try {
      const suppliedKey = req.get("X-API-Key") || "";
      const expected = Buffer.from(API_KEY);
      const supplied = Buffer.from(suppliedKey);

      if (
        supplied.length !== expected.length ||
        !crypto.timingSafeEqual(supplied, expected)
      ) {
        return res.status(401).json({
          ok: false,
          error: "Invalid API key"
        });
      }

      const { consent, message, sender, type, amount, trx_id, trx_time } = req.body || {};

      if (consent !== true) {
        return res.status(403).json({
          ok: false,
          error: "Explicit consent required"
        });
      }

      if (
        typeof message !== "string" ||
        message.trim().length === 0 ||
        message.length > 3000
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid message"
        });
      }

      if (
        sender !== undefined &&
        (typeof sender !== "string" || sender.length > 100)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid sender"
        });
      }

      if (!["sms", "transaction", "test"].includes(type)) {
        return res.status(400).json({
          ok: false,
          error: "Invalid message type"
        });
      }

const ref = await db.collection("twixoMessages").add({
  message: message.trim(),
  sender: sender || "",
  type,
  consent: true,
  amount: amount || "",
  trx_id: trx_id || "",
  trx_time: trx_time || "",
  receivedAt: admin.firestore.FieldValue.serverTimestamp()
});

      return res.status(201).json({
        ok: true,
        id: ref.id,
        message: "Saved to Firestore"
      });
    } catch (error) {
      console.error("TWIXO API error:", error.code || "internal");

      return res.status(500).json({
        ok: false,
        error: "Could not save message"
      });
    }
  }
);

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(`TWIXO API listening on ${port}`);
});
