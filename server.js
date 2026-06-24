const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");

const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"]
}));

app.options("*", cors());

app.use(express.json({ limit: "10mb" }));

app.use((req, res, next) => {
  console.log(req.method + " " + req.url);
  next();
});

if (!process.env.FIREBASE_SERVICE_ACCOUNT) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT");
  process.exit(1);
}

if (!process.env.SMTP_EMAIL || !process.env.SMTP_PASSWORD) {
  console.error("Missing SMTP_EMAIL or SMTP_PASSWORD");
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const transporter = nodemailer.createTransport({
  service: "gmail",
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000,
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASSWORD
  }
});

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Time Lens API is running"
  });
});

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post("/api/auth/send-reset-code", async (req, res) => {
  try {
    console.log("SEND RESET CODE START");

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required"
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    console.log("Checking user:", cleanEmail);

    let user;

    try {
      user = await admin.auth().getUserByEmail(cleanEmail);
      console.log("User found:", user.uid);
    } catch (e) {
      return res.status(404).json({
        success: false,
        message: "This email is not registered"
      });
    }

    const code = generateCode();

    console.log("Generated code:", code);

    await db.collection("passwordResetCodes").doc(cleanEmail).set({
      email: cleanEmail,
      uid: user.uid,
      code: code,
      expiresAt: Date.now() + 10 * 60 * 1000,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log("Code saved in Firestore");

    await transporter.sendMail({
      from: `"Time Lens Team" <${process.env.SMTP_EMAIL}>`,
      to: cleanEmail,
      subject: "Time Lens Password Reset Code",
      html: `
      <div style="font-family:Arial,sans-serif;background:#111827;padding:40px;color:#fff;">
        <div style="max-width:600px;margin:auto;background:#1f2937;border-radius:16px;overflow:hidden;">
          <div style="background:#D4AF37;padding:28px;text-align:center;">
            <h1 style="margin:0;color:#111827;">Time Lens</h1>
            <p style="margin:8px 0 0;color:#111827;">Your Gateway Through History</p>
          </div>

          <div style="padding:35px;">
            <h2 style="color:#D4AF37;">Password Reset Code</h2>
            <p>Hello,</p>
            <p>We received a request to reset your Time Lens account password.</p>
            <p>Your verification code is:</p>

            <div style="background:#111827;border:1px solid #D4AF37;border-radius:12px;padding:20px;text-align:center;margin:25px 0;">
              <span style="color:#D4AF37;font-size:36px;font-weight:bold;letter-spacing:8px;">
                ${code}
              </span>
            </div>

            <p>This code will expire in <b>10 minutes</b>.</p>
            <p>If you did not request this, please ignore this email.</p>

            <hr style="border:none;border-top:1px solid #374151;margin:30px 0;">

            <p style="color:#9ca3af;font-size:14px;">
              Thank you,<br>
              Time Lens Team
            </p>
          </div>
        </div>
      </div>
      `
    });

    console.log("Email sent successfully");

    return res.json({
      success: true,
      message: "Reset code sent successfully"
    });

  } catch (error) {
    console.error("send-reset-code error:", error);

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, code and newPassword are required"
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters"
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const docRef = db.collection("passwordResetCodes").doc(cleanEmail);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(400).json({
        success: false,
        message: "No reset code found"
      });
    }

    const data = doc.data();

    if (data.code !== code.trim()) {
      return res.status(400).json({
        success: false,
        message: "Invalid code"
      });
    }

    if (Date.now() > data.expiresAt) {
      await docRef.delete();

      return res.status(400).json({
        success: false,
        message: "Code expired"
      });
    }

    await admin.auth().updateUser(data.uid, {
      password: newPassword
    });

    await docRef.delete();

    return res.json({
      success: true,
      message: "Password changed successfully"
    });

  } catch (error) {
    console.error("reset-password error:", error);

    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found: " + req.method + " " + req.url
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Time Lens API running on port " + PORT);
});
