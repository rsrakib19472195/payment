const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();

app.disable("x-powered-by");

app.use(
  cors({
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"]
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(express.json({ limit: "16kb" }));

const API_KEY = process.env.TWIXO_API_KEY;
const SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!API_KEY) {
  throw new Error("TWIXO_API_KEY environment variable is missing");
}

if (!SERVICE_ACCOUNT) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON environment variable is missing");
}

let serviceAccount;

try {
  serviceAccount = JSON.parse(SERVICE_ACCOUNT);
} catch (error) {
  throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON");
}

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

/* =========================
   BASIC HELPERS
========================= */

function normalizeTrxId(value) {
  return String(value || "").trim().toUpperCase();
}

function normalizeAmount(value) {
  const n = Number(String(value || "").replace(/[^\d.]/g, ""));
  if (!Number.isFinite(n)) return null;
  return Math.round(n * 100) / 100;
}

function cleanString(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "AURA SKILL Payment API",
    status: "online"
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "AURA SKILL Payment API",
    status: "online",
    time: new Date().toISOString()
  });
});

/* =========================
   MACRODROID → FIRESTORE
========================= */

app.post(
  "/api/messages",
  rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
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

      const {
        consent,
        message,
        sender,
        type,
        amount,
        trx_id,
        trx_time
      } = req.body || {};

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
        sender: cleanString(sender, 100),
        type,
        consent: true,
        amount: cleanString(amount, 50),
        trx_id: cleanString(trx_id, 150),
        trx_time: cleanString(trx_time, 100),
        receivedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      return res.status(201).json({
        ok: true,
        id: ref.id,
        message: "Saved to Firestore"
      });
    } catch (error) {
      console.error("MESSAGE API ERROR:", error);

      return res.status(500).json({
        ok: false,
        error: "Could not save message"
      });
    }
  }
);

/* =========================
   FIREBASE AUTH MIDDLEWARE
========================= */

async function requireFirebaseUser(req, res, next) {
  try {
    const header = req.get("Authorization") || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        ok: false,
        error: "Missing Firebase ID token"
      });
    }

    const idToken = header.substring(7).trim();

    if (!idToken) {
      return res.status(401).json({
        ok: false,
        error: "Invalid Firebase ID token"
      });
    }

    const decoded = await admin.auth().verifyIdToken(idToken);

    req.user = decoded;

    next();
  } catch (error) {
    console.error("AUTH ERROR:", error.code || error.message);

    return res.status(401).json({
      ok: false,
      error: "Authentication failed"
    });
  }
}

/* =========================
   CHECK DUPLICATE TRXID
========================= */

async function transactionAlreadyExists(trxId) {
  const snap = await db
    .collection("transactions")
    .where("trxId", "==", trxId)
    .limit(1)
    .get();

  return !snap.empty;
}

/* =========================
   VERIFY PAYMENT
========================= */

app.post(
  "/api/verify-payment",
  rateLimit({
    windowMs: 60 * 1000,
    limit: 15,
    standardHeaders: true,
    legacyHeaders: false
  }),
  requireFirebaseUser,
  async (req, res) => {
    try {
      const uid = req.user.uid;

      const trxId = normalizeTrxId(req.body?.trxId);
      const requestedAmount = normalizeAmount(req.body?.amount);
      const gateway = cleanString(req.body?.gateway, 50);
      const invoice = cleanString(req.body?.invoice, 150);

      if (!trxId) {
        return res.status(400).json({
          ok: false,
          error: "Transaction ID is required"
        });
      }

      if (requestedAmount === null || requestedAmount <= 0) {
        return res.status(400).json({
          ok: false,
          error: "Invalid payment amount"
        });
      }

      if (!gateway) {
        return res.status(400).json({
          ok: false,
          error: "Payment gateway is required"
        });
      }

      /* =========================
         DUPLICATE CHECK
      ========================= */

      const alreadyUsed = await transactionAlreadyExists(trxId);

      if (alreadyUsed) {
        return res.status(409).json({
          ok: false,
          status: "duplicate",
          error: "এই Transaction ID ইতোমধ্যে ব্যবহার করা হয়েছে।"
        });
      }

      /* =========================
         SEARCH TWIXO MESSAGES
      ========================= */

      const messageSnap = await db
        .collection("twixoMessages")
        .where("trx_id", "==", trxId)
        .limit(10)
        .get();

      if (messageSnap.empty) {
        const reviewRef = await db.collection("transactions").add({
          uid,
          trxId,
          amount: requestedAmount,
          gateway,
          invoice,
          status: "review",
          reviewRequested: true,
          reviewReason: "Transaction ID not found in payment records",
          source: "payment_verification",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        return res.status(200).json({
          ok: true,
          status: "not_found",
          transactionId: reviewRef.id,
          message:
            "এই Transaction ID-এর কোনো payment record পাওয়া যায়নি। Admin Review প্রয়োজন।"
        });
      }

      /* =========================
         FIND AMOUNT MATCH
      ========================= */

      let matchedMessage = null;

      for (const doc of messageSnap.docs) {
        const data = doc.data() || {};

        const savedAmount = normalizeAmount(data.amount);

        if (
          savedAmount !== null &&
          savedAmount === requestedAmount
        ) {
          matchedMessage = {
            id: doc.id,
            data
          };

          break;
        }
      }

      /* =========================
         AMOUNT MISMATCH
      ========================= */

      if (!matchedMessage) {
        const firstData = messageSnap.docs[0].data() || {};

        const foundAmount = normalizeAmount(firstData.amount);

        return res.status(200).json({
          ok: false,
          status: "amount_mismatch",
          requestedAmount,
          foundAmount,
          error:
            "Transaction ID পাওয়া গেছে, কিন্তু payment amount match করেনি।"
        });
      }

      /* =========================
         ATOMIC TRANSACTION
      ========================= */

      const result = await db.runTransaction(async (transaction) => {
        const duplicateQuery = await db
          .collection("transactions")
          .where("trxId", "==", trxId)
          .limit(1)
          .get();

        if (!duplicateQuery.empty) {
          throw new Error("DUPLICATE_TRX");
        }

        const userRef = db.collection("users").doc(uid);

        const userSnap = await transaction.get(userRef);

        if (!userSnap.exists) {
          throw new Error("USER_NOT_FOUND");
        }

        const userData = userSnap.data() || {};

        const currentBalance = normalizeAmount(
          userData.balance ?? userData.wallet ?? 0
        );

        const safeBalance =
          currentBalance === null ? 0 : currentBalance;

        const newBalance =
          Math.round((safeBalance + requestedAmount) * 100) / 100;

        const txRef = db.collection("transactions").doc();

        transaction.set(txRef, {
          uid,
          trxId,
          amount: requestedAmount,
          gateway,
          invoice,
          status: "approved",
          verified: true,
          autoVerified: true,
          walletAdded: requestedAmount,
          source: "payment_verification",
          paymentMessageId: matchedMessage.id,
          paymentSender:
            matchedMessage.data.sender || "",
          paymentTime:
            matchedMessage.data.trx_time || "",
          createdAt:
            admin.firestore.FieldValue.serverTimestamp(),
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp(),
          verifiedAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

        transaction.update(userRef, {
          balance: newBalance,
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

        return {
          transactionId: txRef.id,
          newBalance
        };
      });

      return res.status(200).json({
        ok: true,
        status: "approved",
        transactionId: result.transactionId,
        amount: requestedAmount,
        walletAdded: requestedAmount,
        newBalance: result.newBalance,
        trxId,
        gateway,
        invoice,
        message:
          "Payment verified and wallet updated successfully."
      });
    } catch (error) {
      console.error(
        "VERIFY PAYMENT ERROR:",
        error.code || error.message
      );

      if (error.message === "DUPLICATE_TRX") {
        return res.status(409).json({
          ok: false,
          status: "duplicate",
          error:
            "এই Transaction ID ইতোমধ্যে ব্যবহার করা হয়েছে।"
        });
      }

      if (error.message === "USER_NOT_FOUND") {
        return res.status(404).json({
          ok: false,
          error: "User account not found"
        });
      }

      return res.status(500).json({
        ok: false,
        error:
          "Server payment verification করতে পারেনি।"
      });
    }
  }
);

/* =========================
   ADMIN REVIEW APPROVE
   =========================
   This endpoint is intentionally kept separate.
   Admin authentication should be added according
   to your existing admin system before production use.
========================= */

app.post(
  "/api/admin/review/approve",
  async (req, res) => {
    try {
      const {
        transactionId
      } = req.body || {};

      if (!transactionId) {
        return res.status(400).json({
          ok: false,
          error: "Transaction ID required"
        });
      }

      const txRef = db
        .collection("transactions")
        .doc(transactionId);

      const txSnap = await txRef.get();

      if (!txSnap.exists) {
        return res.status(404).json({
          ok: false,
          error: "Review transaction not found"
        });
      }

      const tx = txSnap.data() || {};

      if (tx.status === "approved") {
        return res.status(409).json({
          ok: false,
          error: "Transaction already approved"
        });
      }

      if (tx.status === "rejected") {
        return res.status(409).json({
          ok: false,
          error: "Transaction already rejected"
        });
      }

      const uid = tx.uid;
      const amount = normalizeAmount(tx.amount);

      if (!uid || amount === null) {
        return res.status(400).json({
          ok: false,
          error: "Invalid review transaction"
        });
      }

      const result = await db.runTransaction(async (transaction) => {
        const userRef = db.collection("users").doc(uid);

        const userSnap = await transaction.get(userRef);

        if (!userSnap.exists) {
          throw new Error("USER_NOT_FOUND");
        }

        const user = userSnap.data() || {};

        const oldBalance =
          normalizeAmount(
            user.balance ?? user.wallet ?? 0
          ) || 0;

        const newBalance =
          Math.round((oldBalance + amount) * 100) / 100;

        transaction.update(txRef, {
          status: "approved",
          verified: true,
          walletAdded: amount,
          approvedManually: true,
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp(),
          approvedAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

        transaction.update(userRef, {
          balance: newBalance,
          updatedAt:
            admin.firestore.FieldValue.serverTimestamp()
        });

        return newBalance;
      });

      return res.json({
        ok: true,
        status: "approved",
        walletAdded: amount,
        newBalance: result
      });
    } catch (error) {
      console.error(
        "ADMIN APPROVE ERROR:",
        error.code || error.message
      );

      return res.status(500).json({
        ok: false,
        error: "Could not approve review"
      });
    }
  }
);

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Endpoint not found",
    path: req.path
  });
});

/* =========================
   GLOBAL ERROR HANDLER
========================= */

app.use((error, req, res, next) => {
  console.error("GLOBAL ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    ok: false,
    error: "Internal server error"
  });
});

/* =========================
   START
========================= */

const port = process.env.PORT || 3000;

app.listen(port, "0.0.0.0", () => {
  console.log(
    `AURA SKILL Payment API running on port ${port}`
  );
});
