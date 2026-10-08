const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();

app.disable("x-powered-by");

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

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


// =====================================================
// HELPERS
// =====================================================

function normalizeTrx(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function normalizeAmount(value) {
  if (value === null || value === undefined) {
    return null;
  }

  const cleaned = String(value)
    .replace(/[^\d.]/g, "")
    .trim();

  if (!cleaned) {
    return null;
  }

  const number = Number(cleaned);

  if (!Number.isFinite(number)) {
    return null;
  }

  return Math.round(number * 100) / 100;
}

function safeString(value, max = 300) {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().slice(0, max);
}

function checkApiKey(req) {
  const suppliedKey = req.get("X-API-Key") || "";

  const expected = Buffer.from(API_KEY);
  const supplied = Buffer.from(suppliedKey);

  if (expected.length !== supplied.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, supplied);
}


// =====================================================
// FIREBASE AUTH
// =====================================================

async function verifyUser(req) {
  const authorization =
    req.get("Authorization") || "";

  if (!authorization.startsWith("Bearer ")) {
    throw new Error("AUTH_REQUIRED");
  }

  const token =
    authorization.substring(7).trim();

  if (!token) {
    throw new Error("AUTH_REQUIRED");
  }

  return await admin.auth().verifyIdToken(token);
}


// =====================================================
// HEALTH
// =====================================================

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "TWIXO API"
  });
});


// =====================================================
// MACRODROID -> TWIXO MESSAGES
// =====================================================

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

      if (!checkApiKey(req)) {
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
        !message.trim() ||
        message.length > 3000
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid message"
        });
      }


      if (
        sender !== undefined &&
        (
          typeof sender !== "string" ||
          sender.length > 100
        )
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid sender"
        });
      }


      if (
        !["sms", "transaction", "test"].includes(type)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid message type"
        });
      }


      const normalizedTrx =
        normalizeTrx(trx_id);


      const ref =
        await db
          .collection("twixoMessages")
          .add({

            message: message.trim(),

            sender: sender || "",

            type,

            consent: true,

            amount:
              amount !== undefined &&
              amount !== null
                ? String(amount)
                : "",

            trx_id: normalizedTrx,

            trx_time:
              trx_time !== undefined &&
              trx_time !== null
                ? String(trx_time)
                : "",

            receivedAt:
              admin.firestore.FieldValue
                .serverTimestamp()
          });


      return res.status(201).json({

        ok: true,

        id: ref.id,

        message: "Saved to Firestore"
      });


    } catch (error) {

      console.error(
        "TWIXO API error:",
        error.code ||
        error.message ||
        "internal"
      );

      return res.status(500).json({

        ok: false,

        error: "Could not save message"
      });
    }
  }
);


// =====================================================
// AUTO VERIFY PAYMENT
// =====================================================

app.post(
  "/api/verify-payment",
  rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false
  }),
  async (req, res) => {

    try {

      // -------------------------------------------------
      // FIREBASE LOGIN VERIFY
      // -------------------------------------------------

      let decodedUser;

      try {

        decodedUser =
          await verifyUser(req);

      } catch (error) {

        return res.status(401).json({

          ok: false,

          status: "unauthorized",

          error:
            "আপনার login session পাওয়া যায়নি। আবার login করুন।"
        });
      }


      const userId =
        decodedUser.uid;


      // -------------------------------------------------
      // REQUEST DATA
      // -------------------------------------------------

      const {
        trxId,
        amount,
        gateway,
        invoice
      } = req.body || {};


      const trx =
        normalizeTrx(trxId);

      const requestedAmount =
        normalizeAmount(amount);

      const selectedGateway =
        safeString(gateway, 50);

      const invoiceNo =
        safeString(invoice, 100);


      // -------------------------------------------------
      // VALIDATION
      // -------------------------------------------------

      if (!trx) {

        return res.status(400).json({

          ok: false,

          status: "invalid",

          error:
            "TrxID দিন।"
        });
      }


      if (
        requestedAmount === null ||
        requestedAmount <= 0
      ) {

        return res.status(400).json({

          ok: false,

          status: "invalid",

          error:
            "Amount সঠিক নয়।"
        });
      }


      // -------------------------------------------------
      // USER CHECK
      // -------------------------------------------------

      const userRef =
        db.collection("users").doc(userId);

      const userSnap =
        await userRef.get();


      if (!userSnap.exists) {

        return res.status(404).json({

          ok: false,

          status: "invalid",

          error:
            "আপনার user account পাওয়া যায়নি।"
        });
      }


      // -------------------------------------------------
      // DUPLICATE TRX CHECK
      // -------------------------------------------------

      const duplicateSnap =
        await db
          .collection("transactions")
          .where("trxId", "==", trx)
          .limit(20)
          .get();


      if (!duplicateSnap.empty) {

        return res.status(409).json({

          ok: false,

          status: "duplicate",

          error:
            "এই TrxID ইতিমধ্যে ব্যবহার করা হয়েছে। একই TrxID দ্বিতীয়বার ব্যবহার করা যাবে না।"
        });
      }


      // -------------------------------------------------
      // SEARCH TWIXO MESSAGES
      // -------------------------------------------------

      const twixoSnap =
        await db
          .collection("twixoMessages")
          .where("trx_id", "==", trx)
          .limit(10)
          .get();


      // -------------------------------------------------
      // TRX NOT FOUND
      // -------------------------------------------------

      if (twixoSnap.empty) {

        const reviewRef =
          db.collection("transactions").doc();


        await reviewRef.set({

          userId,

          userEmail:
            decodedUser.email || "",

          userName:
            decodedUser.name ||
            decodedUser.email?.split("@")[0] ||
            "User",

          amount: requestedAmount,

          fee: 0,

          total: requestedAmount,

          gateway:
            selectedGateway,

          method:
            selectedGateway,

          trxId: trx,

          transactionId: trx,

          invoice:
            invoiceNo,

          status:
            "review",

          reviewRequired:
            true,

          reviewReason:
            "TrxID twixoMessages-এ পাওয়া যায়নি।",

          autoVerified:
            false,

          createdAt:
            admin.firestore.FieldValue
              .serverTimestamp(),

          updatedAt:
            admin.firestore.FieldValue
              .serverTimestamp()
        });


        return res.status(200).json({

          ok: false,

          status:
            "not_found",

          reviewRequired:
            true,

          transactionId:
            reviewRef.id,

          error:
            "এই TrxID খুঁজে পাওয়া যায়নি। আপনার payment সত্যিই হয়ে থাকলে Admin Review-তে পাঠানো হয়েছে।"
        });
      }


      // -------------------------------------------------
      // AMOUNT MATCH
      // -------------------------------------------------

      let matchedMessage = null;
      let matchedMessageId = null;


      twixoSnap.forEach(doc => {

        const data =
          doc.data() || {};

        const messageTrx =
          normalizeTrx(data.trx_id);

        const messageAmount =
          normalizeAmount(data.amount);


        if (
          messageTrx === trx &&
          messageAmount !== null &&
          messageAmount === requestedAmount
        ) {

          matchedMessage =
            data;

          matchedMessageId =
            doc.id;
        }
      });


      // -------------------------------------------------
      // AMOUNT MISMATCH
      // -------------------------------------------------

      if (!matchedMessage) {

        return res.status(400).json({

          ok: false,

          status:
            "amount_mismatch",

          error:
            "Payment পাওয়া গেছে, কিন্তু Amount মেলেনি। আপনি যে Amount দিয়েছেন এবং payment notification-এর Amount একই নয়।"
        });
      }


      // -------------------------------------------------
      // PREPARE VERIFIED DATA
      // -------------------------------------------------

      const sender =
        safeString(
          matchedMessage.sender,
          100
        );

      const trxTime =
        safeString(
          matchedMessage.trx_time,
          100
        );

      const verifiedAmount =
        normalizeAmount(
          matchedMessage.amount
        );


      // -------------------------------------------------
      // ATOMIC WALLET CREDIT
      // -------------------------------------------------

      const transactionRef =
        db.collection("transactions").doc();


      const result =
        await db.runTransaction(
          async transaction => {

            // ===========================================
            // RE-CHECK DUPLICATE INSIDE TRANSACTION
            // ===========================================

            const duplicateCheck =
              await db
                .collection("transactions")
                .where("trxId", "==", trx)
                .limit(20)
                .get();


            if (!duplicateCheck.empty) {

              throw new Error(
                "TRX_ALREADY_USED"
              );
            }


            // ===========================================
            // READ USER
            // ===========================================

            const freshUserSnap =
              await transaction.get(userRef);


            if (!freshUserSnap.exists) {

              throw new Error(
                "USER_NOT_FOUND"
              );
            }


            const userData =
              freshUserSnap.data() || {};


            const oldBalance =
              normalizeAmount(
                userData.balance || 0
              ) || 0;


            const newBalance =
              Math.round(
                (oldBalance + verifiedAmount) *
                100
              ) / 100;


            // ===========================================
            // TRANSACTION RECORD
            // ===========================================

            transaction.set(
              transactionRef,
              {

                userId,

                userEmail:
                  decodedUser.email || "",

                userName:
                  decodedUser.name ||
                  decodedUser.email?.split("@")[0] ||
                  "User",

                amount:
                  verifiedAmount,

                fee: 0,

                total:
                  verifiedAmount,

                gateway:
                  selectedGateway,

                method:
                  selectedGateway,

                trxId:
                  trx,

                transactionId:
                  trx,

                invoice:
                  invoiceNo,

                status:
                  "approved",

                autoVerified:
                  true,

                verified:
                  true,

                reviewRequired:
                  false,

                matchedMessageId:
                  matchedMessageId,

                verifiedSender:
                  sender,

                verifiedAmount:
                  verifiedAmount,

                verifiedTrxTime:
                  trxTime,

                walletBalanceBefore:
                  oldBalance,

                walletBalanceAfter:
                  newBalance,

                createdAt:
                  admin.firestore.FieldValue
                    .serverTimestamp(),

                verifiedAt:
                  admin.firestore.FieldValue
                    .serverTimestamp(),

                updatedAt:
                  admin.firestore.FieldValue
                    .serverTimestamp()
              }
            );


            // ===========================================
            // WALLET UPDATE
            // ===========================================

            transaction.update(
              userRef,
              {

                balance:
                  admin.firestore.FieldValue
                    .increment(verifiedAmount),

                updatedAt:
                  admin.firestore.FieldValue
                    .serverTimestamp()
              }
            );


            return {

              transactionId:
                transactionRef.id,

              oldBalance,

              newBalance,

              verifiedAmount
            };
          }
        );


      // -------------------------------------------------
      // SUCCESS
      // -------------------------------------------------

      return res.status(200).json({

        ok: true,

        status:
          "approved",

        verified:
          true,

        autoVerified:
          true,

        transactionId:
          result.transactionId,

        trxId:
          trx,

        amount:
          result.verifiedAmount,

        sender,

        trxTime,

        balanceBefore:
          result.oldBalance,

        balanceAfter:
          result.newBalance,

        message:
          "Payment সফলভাবে verify হয়েছে এবং wallet-এ balance যোগ হয়েছে।"
      });


    } catch (error) {

      console.error(
        "VERIFY PAYMENT ERROR:",
        error.code ||
        error.message ||
        error
      );


      if (
        error.message ===
        "TRX_ALREADY_USED"
      ) {

        return res.status(409).json({

          ok: false,

          status:
            "duplicate",

          error:
            "এই TrxID ইতিমধ্যে ব্যবহার করা হয়েছে।"
        });
      }


      if (
        error.message ===
        "USER_NOT_FOUND"
      ) {

        return res.status(404).json({

          ok: false,

          status:
            "invalid",

          error:
            "User account পাওয়া যায়নি।"
        });
      }


      return res.status(500).json({

        ok: false,

        status:
          "server_error",

        error:
          "Payment verify করার সময় server error হয়েছে। কিছুক্ষণ পরে আবার চেষ্টা করুন।"
      });
    }
  }
);


// =====================================================
// START SERVER
// =====================================================

const port =
  process.env.PORT || 3000;


app.listen(
  port,
  "0.0.0.0",
  () => {

    console.log(
      `TWIXO API listening on ${port}`
    );
  }
);
