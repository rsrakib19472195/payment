const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();

app.disable("x-powered-by");

app.use(helmet());

app.use(
  express.json({
    limit: "16kb"
  })
);

const API_KEY =
  process.env.TWIXO_API_KEY;

const SERVICE_ACCOUNT =
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!API_KEY || !SERVICE_ACCOUNT) {
  throw new Error(
    "Required environment variables are missing"
  );
}

admin.initializeApp({
  credential:
    admin.credential.cert(
      JSON.parse(SERVICE_ACCOUNT)
    )
});

const db =
  admin.firestore();

const FieldValue =
  admin.firestore.FieldValue;


/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/health",
  (req, res) => {

    res.json({
      ok: true,
      service: "AURA SKILL Payment API",
      status: "online",
      time: new Date().toISOString()
    });

  }
);


/* =========================================================
   MACRODROID MESSAGE SAVE
========================================================= */

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

      const suppliedKey =
        req.get("X-API-Key") || "";

      const expected =
        Buffer.from(API_KEY);

      const supplied =
        Buffer.from(suppliedKey);

      if (
        supplied.length !==
          expected.length ||
        !crypto.timingSafeEqual(
          supplied,
          expected
        )
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
          error:
            "Explicit consent required"
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
        ![
          "sms",
          "transaction",
          "test"
        ].includes(type)
      ) {

        return res.status(400).json({
          ok: false,
          error: "Invalid message type"
        });

      }


      const ref =
        await db
          .collection("twixoMessages")
          .add({

            message:
              message.trim(),

            sender:
              sender || "",

            type,

            consent: true,

            amount:
              amount || "",

            trx_id:
              trx_id || "",

            trx_time:
              trx_time || "",

            receivedAt:
              FieldValue.serverTimestamp()

          });


      return res.status(201).json({

        ok: true,

        id: ref.id,

        message:
          "Saved to Firestore"

      });


    } catch (error) {

      console.error(
        "TWIXO API error:",
        error.code ||
          "internal"
      );

      return res.status(500).json({

        ok: false,

        error:
          "Could not save message"

      });

    }

  }
);


/* =========================================================
   FIREBASE AUTH MIDDLEWARE
========================================================= */

async function authenticateFirebaseUser(
  req,
  res,
  next
){

  try {

    const header =
      req.get("Authorization") || "";


    if (
      !header.startsWith(
        "Bearer "
      )
    ) {

      return res.status(401).json({

        ok: false,

        status:
          "unauthorized",

        error:
          "Firebase login required"

      });

    }


    const idToken =
      header.substring(7).trim();


    if (!idToken) {

      return res.status(401).json({

        ok: false,

        status:
          "unauthorized",

        error:
          "Missing Firebase ID token"

      });

    }


    const decoded =
      await admin
        .auth()
        .verifyIdToken(
          idToken
        );


    req.firebaseUser =
      decoded;


    next();


  } catch (error) {

    console.error(
      "Firebase auth error:",
      error.code ||
        "invalid-token"
    );


    return res.status(401).json({

      ok: false,

      status:
        "unauthorized",

      error:
        "Invalid or expired login session"

    });

  }

}


/* =========================================================
   PAYMENT VERIFY
========================================================= */

app.post(
  "/api/verify-payment",

  rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false
  }),

  authenticateFirebaseUser,

  async (req, res) => {

    try {

      const user =
        req.firebaseUser;


      const uid =
        user.uid;


      const email =
        user.email || "";


      let {
        trxId,
        amount,
        gateway,
        invoice
      } = req.body || {};


      trxId =
        String(
          trxId || ""
        ).trim();


      amount =
        Number(amount);


      gateway =
        String(
          gateway || ""
        ).trim();


      invoice =
        String(
          invoice || ""
        ).trim();


      /* ================================================
         BASIC VALIDATION
      ================================================ */

      if (
        !trxId ||
        trxId.length < 4 ||
        trxId.length > 100
      ) {

        return res.status(400).json({

          ok: false,

          status:
            "invalid",

          error:
            "Invalid Transaction ID"

        });

      }


      if (
        !Number.isFinite(amount) ||
        amount < 10 ||
        amount > 10000000
      ) {

        return res.status(400).json({

          ok: false,

          status:
            "invalid",

          error:
            "Invalid payment amount"

        });

      }


      if (
        ![
          "Bkash",
          "Nagad"
        ].includes(gateway)
      ) {

        return res.status(400).json({

          ok: false,

          status:
            "invalid",

          error:
            "Invalid payment gateway"

        });

      }


      const requestedAmount =
        Math.round(
          amount * 100
        ) / 100;


      /* ================================================
         SAME TRXID CHECK
         ANY USER / ANY GATEWAY
         ================================================ */

      const existingTxSnap =
        await db
          .collection("transactions")
          .where(
            "trxId",
            "==",
            trxId
          )
          .limit(1)
          .get();


      if (
        !existingTxSnap.empty
      ) {

        return res.status(409).json({

          ok: false,

          status:
            "duplicate",

          error:
            "এই TrxID ইতিমধ্যে ব্যবহার করা হয়েছে। একই TrxID দ্বিতীয়বার ব্যবহার করা যাবে না।"

        });

      }


      /* ================================================
         FIND MACRODROID MESSAGE
      ================================================ */

      const messageSnap =
        await db
          .collection("twixoMessages")
          .where(
            "trx_id",
            "==",
            trxId
          )
          .limit(20)
          .get();


      if (
        messageSnap.empty
      ) {

        /* ============================================
           CREATE REVIEW TRANSACTION
        ============================================ */

        const reviewRef =
          db
            .collection("transactions")
            .doc();


        await reviewRef.set({

          userId:
            uid,

          userEmail:
            email,

          userName:
            user.name ||
            user.email?.split("@")[0] ||
            "User",

          amount:
            requestedAmount,

          fee: 0,

          total:
            requestedAmount,

          gateway,

          method:
            gateway,

          trxId,

          transactionId:
            reviewRef.id,

          invoice,

          status:
            "review",

          reviewReason:
            "TrxID not found in MacroDroid payment messages.",

          source:
            "automatic-payment-verification",

          createdAt:
            FieldValue.serverTimestamp(),

          updatedAt:
            FieldValue.serverTimestamp()

        });


        return res.status(200).json({

          ok: false,

          status:
            "not_found",

          transactionId:
            reviewRef.id,

          error:
            "এই TrxID MacroDroid payment notification system-এ পাওয়া যায়নি।"

        });

      }


      /* ================================================
         CHECK ALL MATCH CONDITIONS
      ================================================ */

      let matchedMessage =
        null;

      let amountMismatch =
        false;

      let messageMismatch =
        false;


      for (
        const docSnap
        of messageSnap.docs
      ) {

        const data =
          docSnap.data() || {};


        const storedAmount =
          Number(
            String(
              data.amount || ""
            )
            .replace(
              /,/g,
              ""
            )
          );


        const storedMessage =
          String(
            data.message || ""
          )
          .trim()
          .toLowerCase();


        const storedType =
          String(
            data.type || ""
          )
          .trim()
          .toLowerCase();


        const consent =
          data.consent === true;


        /* ==========================================
           MESSAGE CHECK
        ========================================== */

        let expectedMessage;


        if (
          gateway ===
          "Nagad"
        ) {

          expectedMessage =
            "nagad transaction";

        } else {

          expectedMessage =
            "bkash transaction";

        }


        const messageOk =
          storedMessage ===
            expectedMessage ||
          storedMessage.includes(
            expectedMessage
          );


        const amountOk =
          Number.isFinite(
            storedAmount
          ) &&
          Math.abs(
            storedAmount -
              requestedAmount
          ) < 0.001;


        const typeOk =
          storedType ===
            "sms" ||
          storedType ===
            "transaction";


        if (
          !amountOk
        ) {

          amountMismatch =
            true;

        }


        if (
          !messageOk
        ) {

          messageMismatch =
            true;

        }


        if (
          amountOk &&
          messageOk &&
          typeOk &&
          consent
        ) {

          matchedMessage = {

            id:
              docSnap.id,

            ...data

          };

          break;

        }

      }


      /* ================================================
         TRX FOUND BUT AMOUNT/MESSAGE WRONG
      ================================================ */

      if (
        !matchedMessage
      ) {

        if (
          amountMismatch
        ) {

          return res.status(200).json({

            ok: false,

            status:
              "amount_mismatch",

            error:
              "Payment notification পাওয়া গেছে, কিন্তু Amount মেলেনি।"

          });

        }


        if (
          messageMismatch
        ) {

          return res.status(200).json({

            ok: false,

            status:
              "message_mismatch",

            error:
              "TrxID পাওয়া গেছে, কিন্তু MacroDroid payment message match করেনি।"

          });

        }


        return res.status(200).json({

          ok: false,

          status:
            "not_found",

          error:
            "Valid payment notification match পাওয়া যায়নি।"

        });

      }


      /* ================================================
         EXTRACT MACRO DATA
      ================================================ */

      const sender =
        String(
          matchedMessage.sender ||
          ""
        );


      const trxTime =
        String(
          matchedMessage.trx_time ||
          ""
        );


      const verifiedAmount =
        Math.round(
          Number(
            matchedMessage.amount
          ) * 100
        ) / 100;


      /* ================================================
         ATOMIC WALLET + TRANSACTION
      ================================================ */

      const userRef =
        db
          .collection("users")
          .doc(uid);


      const transactionRef =
        db
          .collection("transactions")
          .doc();


      let balanceBefore = 0;

      let balanceAfter = 0;


      await db.runTransaction(
        async transaction => {

          /* ==========================================
             RE-CHECK TRXID INSIDE ATOMIC TRANSACTION
          ========================================== */

          const duplicateSnap =
            await transaction.get(
              db
                .collection(
                  "transactions"
                )
                .where(
                  "trxId",
                  "==",
                  trxId
                )
                .limit(1)
            );


          if (
            !duplicateSnap.empty
          ) {

            throw new Error(
              "DUPLICATE_TRXID"
            );

          }


          const userSnap =
            await transaction.get(
              userRef
            );


          if (
            !userSnap.exists
          ) {

            throw new Error(
              "USER_NOT_FOUND"
            );

          }


          const userData =
            userSnap.data() || {};


          balanceBefore =
            Number(
              userData.balance || 0
            );


          if (
            !Number.isFinite(
              balanceBefore
            )
          ) {

            balanceBefore =
              0;

          }


          balanceAfter =
            Math.round(
              (
                balanceBefore +
                verifiedAmount
              ) * 100
            ) / 100;


          /* ==========================================
             UPDATE USER WALLET
          ========================================== */

          transaction.update(
            userRef,
            {

              balance:
                balanceAfter,

              updatedAt:
                FieldValue.serverTimestamp()

            }
          );


          /* ==========================================
             CREATE APPROVED TRANSACTION
          ========================================== */

          transaction.set(
            transactionRef,
            {

              userId:
                uid,

              userEmail:
                email,

              userName:
                user.name ||
                user.email?.split("@")[0] ||
                "User",

              amount:
                verifiedAmount,

              fee: 0,

              total:
                verifiedAmount,

              gateway,

              method:
                gateway,

              trxId,

              transactionId:
                transactionRef.id,

              invoice,

              status:
                "approved",

              verified:
                true,

              autoVerified:
                true,

              source:
                "macrodroid",

              messageId:
                matchedMessage.id,

              sender,

              trxTime,

              message:
                matchedMessage.message ||
                "",

              balanceBefore,

              balanceAfter,

              createdAt:
                FieldValue.serverTimestamp(),

              updatedAt:
                FieldValue.serverTimestamp(),

              approvedAt:
                FieldValue.serverTimestamp()

            }
          );

        }
      );


      /* ================================================
         SUCCESS
      ================================================ */

      return res.status(200).json({

        ok: true,

        status:
          "approved",

        transactionId:
          transactionRef.id,

        trxId,

        amount:
          verifiedAmount,

        gateway,

        sender,

        trxTime,

        balanceBefore,

        balanceAfter,

        walletAdded:
          verifiedAmount

      });


    } catch (error) {

      console.error(
        "VERIFY PAYMENT ERROR:",
        error.message ||
          error
      );


      if (
        error.message ===
        "DUPLICATE_TRXID"
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
            "user_not_found",

          error:
            "User wallet পাওয়া যায়নি।"

        });

      }


      return res.status(500).json({

        ok: false,

        status:
          "server_error",

        error:
          "Payment verification failed."

      });

    }

  }
);


/* =========================================================
   SERVER
========================================================= */

const port =
  process.env.PORT || 3000;


app.listen(
  port,
  "0.0.0.0",
  () => {

    console.log(
      `AURA SKILL Payment API listening on ${port}`
    );

  }
);
