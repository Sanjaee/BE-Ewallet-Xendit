// File: server.js
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const Xendit = require("xendit-node");
const cors = require("cors");

const axios = require("axios");
require("dotenv").config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
app.use(cors()); // Menggunakan cors() tanpa parameter untuk mengizinkan semua origin, sesuai dengan `cors({ origin: "*" });` yang dikomentari

// Initialize Xendit (menggunakan xendit-node library, meskipun endpoint topup masih pakai axios langsung)
const xendit = new Xendit({
  secretKey: process.env.XENDIT_SECRET_KEY,
});

// Xendit services (disbursementService digunakan di endpoint lain, eWalletService di testXenditConnection)
const { Disbursement, EWallet } = xendit;
const disbursementService = new Disbursement({});
const eWalletService = new EWallet({});

app.use(express.json());

// Middleware for authentication
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized: Token required" });
    }

    const user = await prisma.user.findUnique({
      where: { token },
    });

    if (!user) {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ error: "Server error during authentication" });
  }
};

// Register new user
app.post("/api/users/register", async (req, res) => {
  try {
    const { name, email, password, phoneNumber } = req.body;

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "User with this email already exists" });
    }

    // Create new user
    const token = generateToken();
    const newUser = await prisma.user.create({
      data: {
        name,
        email,
        password: hashPassword(password), // You should implement proper password hashing
        phoneNumber,
        token,
        balance: 0,
      },
    });

    res.status(201).json({
      message: "User registered successfully",
      data: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        token: newUser.token,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Server error during registration" });
  }
});

// Login
app.post("/api/users/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user || user.password !== hashPassword(password)) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    res.status(200).json({
      message: "Login successful",
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        phoneNumber: user.phoneNumber,
        token: user.token,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error during login" });
  }
});

app.post("/api/users/change-password", authenticateUser, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ error: "Both old and new passwords are required" });
    }

    // Ambil user dari req.user (dari token)
    const user = req.user;

    // Cek apakah password lama cocok
    const hashedOld = hashPassword(oldPassword);
    if (user.password !== hashedOld) {
      return res.status(401).json({ error: "Old password is incorrect" });
    }

    // Update password dengan yang baru
    const hashedNew = hashPassword(newPassword);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedNew },
    });

    res.status(200).json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Password update error:", err);
    res.status(500).json({ error: "Server error during password update" });
  }
});

// Get user balance
app.get("/api/users/balance", authenticateUser, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { balance: true },
    });

    res.status(200).json({
      message: "Balance fetched successfully",
      data: {
        balance: user.balance,
      },
    });
  } catch (error) {
    console.error("Balance fetch error:", error);
    res.status(500).json({ error: "Server error while fetching balance" });
  }
});

// Fix untuk callback URL dan webhook handling
const IS_DEVELOPMENT = process.env.NODE_ENV !== "production";

// Update endpoint topup dengan callback URL yang benar
app.post("/api/wallet/topup", authenticateUser, async (req, res) => {
  try {
    const { amount, paymentMethod } = req.body;
    const userId = req.user.id;

    // Validate input
    if (!amount || !paymentMethod) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (amount < 10000) {
      return res.status(400).json({ error: "Minimum amount is 10,000" });
    }

    // Generate unique reference ID
    const referenceId = `topup-${userId}-${Date.now()}`;

    // PERBAIKAN: Pastikan callback URL lengkap dan konsisten
    const callbackUrl = IS_DEVELOPMENT
      ? `${process.env.NGROK_URL}/api/xendit/callback` // Full path untuk webhook
      : `${process.env.PRODUCTION_URL}/api/xendit/callback`;

    console.log("Using callback URL:", callbackUrl);

    // Prepare Xendit request
    const xenditData = {
      reference_id: referenceId,
      currency: "IDR",
      amount: amount,
      checkout_method: "ONE_TIME_PAYMENT",
      channel_code: paymentMethod,
      channel_properties: {
        success_redirect_url: process.env.SUCCESS_REDIRECT_URL || "http://localhost:3001",
        failure_redirect_url: process.env.FAILURE_REDIRECT_URL || "http://localhost:3001/failure",
      },
      // PENTING: Pastikan callback URL lengkap
      callback_url: callbackUrl,
      metadata: {
        userId: userId,
        paymentMethod: paymentMethod,
      },
    };

    console.log("Sending request to Xendit:", xenditData);

    const xenditResponse = await fetch(
      "https://api.xendit.co/ewallets/charges",
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${Buffer.from(
            process.env.XENDIT_SECRET_KEY + ":"
          ).toString("base64")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(xenditData),
      }
    );

    const xenditResult = await xenditResponse.json();
    console.log("Xendit response:", xenditResult);

    if (!xenditResponse.ok) {
      throw new Error(xenditResult.message || "Xendit API error");
    }

    // Create transaction record
    const transaction = await prisma.transaction.create({
      data: {
        userId: userId,
        type: "TOPUP",
        amount: amount,
        status: "PENDING",
        referenceId: referenceId,
        xenditPaymentRequestId: xenditResult.id,
        description: `Top up via ${paymentMethod}`,
      },
    });

    console.log("Transaction created:", transaction);

    // Determine checkout URL
    let checkoutUrl = null;
    if (xenditResult.is_redirect_required && xenditResult.actions) {
      checkoutUrl =
        xenditResult.actions.desktop_web_checkout_url ||
        xenditResult.actions.mobile_web_checkout_url ||
        xenditResult.actions.mobile_deeplink_checkout_url;
    }

    const responseData = {
      success: true,
      data: {
        referenceId: referenceId,
        status: xenditResult.status,
        paymentId: xenditResult.id,
        checkoutUrl: checkoutUrl,
        isRedirectRequired: xenditResult.is_redirect_required || false,
        qrString: xenditResult.actions?.qr_checkout_string || null,
      },
    };

    console.log("Sending response:", responseData);
    res.json(responseData);
  } catch (error) {
    console.error("Top up error:", error);
    res.status(500).json({
      error: "Failed to process top up",
      details: error.message,
    });
  }
});

// PERBAIKAN: Enhanced Webhook Callback Endpoint dengan lebih banyak logging
app.post("/api/xendit/callback", async (req, res) => {
  try {
    console.log("=== XENDIT CALLBACK RECEIVED ===");
    console.log("Timestamp:", new Date().toISOString());
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("Body:", JSON.stringify(req.body, null, 2));

    const { event, data, id, status, reference_id, metadata } = req.body;

    // Handle multiple callback formats
    const transactionReferenceId =
      reference_id || data?.reference_id || data?.id;
    const transactionStatus =
      status ||
      data?.status ||
      (event === "ewallet.payment.succeeded"
        ? "SUCCEEDED"
        : event === "ewallet.payment.failed"
        ? "FAILED"
        : "PENDING");

    console.log("Extracted reference_id:", transactionReferenceId);
    console.log("Extracted status:", transactionStatus);

    if (!transactionReferenceId) {
      console.log("ERROR: No reference_id found in callback");
      return res.status(400).json({ error: "Missing reference_id" });
    }

    // Find the transaction
    const transaction = await prisma.transaction.findFirst({
      where: {
        referenceId: transactionReferenceId,
      },
      include: {
        user: true, // Include user data for balance update
      },
    });

    if (!transaction) {
      console.log(
        `ERROR: Transaction not found for reference: ${transactionReferenceId}`
      );
      return res.status(404).json({ error: "Transaction not found" });
    }

    console.log("Found transaction:", {
      id: transaction.id,
      amount: transaction.amount,
      currentStatus: transaction.status,
      userId: transaction.userId,
      userCurrentBalance: transaction.user.balance,
    });

    // PERBAIKAN: Map status dengan lebih tepat
    let mappedStatus = "PENDING";
    if (
      transactionStatus === "SUCCEEDED" ||
      transactionStatus === "COMPLETED" ||
      event === "ewallet.payment.succeeded"
    ) {
      mappedStatus = "COMPLETED";
    } else if (
      transactionStatus === "FAILED" ||
      transactionStatus === "CANCELLED" ||
      event === "ewallet.payment.failed"
    ) {
      mappedStatus = "FAILED";
    }

    console.log("Mapped status:", mappedStatus);

    // Update transaction status
    const updatedTransaction = await prisma.transaction.update({
      where: {
        id: transaction.id,
      },
      data: {
        status: mappedStatus,
        updatedAt: new Date(),
      },
    });

    console.log(
      `Transaction ${transactionReferenceId} updated to status: ${mappedStatus}`
    );

    // PERBAIKAN: Update user balance jika pembayaran berhasil
    let updatedUser = null;
    if (mappedStatus === "COMPLETED") {
      console.log(`Updating user balance for user: ${transaction.userId}`);
      console.log(`Current balance: ${transaction.user.balance}`);
      console.log(`Adding amount: ${transaction.amount}`);

      updatedUser = await prisma.user.update({
        where: {
          id: transaction.userId,
        },
        data: {
          balance: {
            increment: transaction.amount,
          },
        },
      });

      console.log(`SUCCESS: User ${transaction.userId} balance updated!`);
      console.log(`Previous balance: ${transaction.user.balance}`);
      console.log(`New balance: ${updatedUser.balance}`);
      console.log(`Amount added: ${transaction.amount}`);
    }

    // Send success response
    const response = {
      received: true,
      reference_id: transactionReferenceId,
      status: mappedStatus,
      transaction_id: transaction.id,
      user_balance: updatedUser
        ? updatedUser.balance
        : transaction.user.balance,
      processed_at: new Date().toISOString(),
    };

    console.log("Sending callback response:", response);
    res.status(200).json(response);
  } catch (error) {
    console.error("WEBHOOK ERROR:", error);
    console.error("Error stack:", error.stack);
    res.status(500).json({
      error: "Webhook processing failed",
      message: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// PERBAIKAN: Enhanced Status Check Endpoint
app.get(
  "/api/wallet/topup/status/:referenceId",
  authenticateUser,
  async (req, res) => {
    try {
      const { referenceId } = req.params;
      console.log(`Checking status for reference: ${referenceId}`);

      const transaction = await prisma.transaction.findFirst({
        where: {
          referenceId: referenceId,
        },
        include: {
          user: {
            select: {
              balance: true,
            },
          },
        },
      });

      if (!transaction) {
        console.log(`Transaction not found: ${referenceId}`);
        return res.status(404).json({ error: "Transaction not found" });
      }

      // Check if transaction belongs to the authenticated user
      if (transaction.userId !== req.user.id) {
        console.log(
          `Unauthorized access attempt for transaction: ${referenceId}`
        );
        return res.status(403).json({ error: "Unauthorized" });
      }

      const response = {
        status: transaction.status,
        amount: transaction.amount,
        referenceId: transaction.referenceId,
        currentBalance: transaction.user.balance,
        createdAt: transaction.createdAt,
        updatedAt: transaction.updatedAt,
      };

      console.log(`Status check response:`, response);
      res.json(response);
    } catch (error) {
      console.error("Status check error:", error);
      res.status(500).json({ error: "Failed to check payment status" });
    }
  }
);

// TAMBAHAN: Endpoint untuk debug webhook (opsional)
app.get(
  "/api/debug/transaction/:referenceId",
  authenticateUser,
  async (req, res) => {
    try {
      const { referenceId } = req.params;

      const transaction = await prisma.transaction.findFirst({
        where: {
          referenceId: referenceId,
        },
        include: {
          user: true,
        },
      });

      if (!transaction) {
        return res.status(404).json({ error: "Transaction not found" });
      }

      res.json({
        transaction,
        debug_info: {
          current_time: new Date().toISOString(),
          callback_url_used: IS_DEVELOPMENT
            ? `${NGROK_URL}/api/xendit/callback`
            : `${process.env.PRODUCTION_URL}/api/xendit/callback`,
        },
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);

// Xendit debugging middleware
const debugXendit = async (req, res, next) => {
  const originalSend = res.send;

  // Wrap the send method to log API responses
  res.send = function (data) {
    if (req.path.includes("/api/wallet")) {
      try {
        const responseData = JSON.parse(data);
        console.log(`[${req.method}] ${req.path} Response:`, responseData);
      } catch (e) {
        console.log(`[${req.method}] ${req.path} Raw Response:`, data);
      }
    }
    originalSend.call(this, data);
  };

  // Log request details
  if (req.path.includes("/api/wallet")) {
    console.log(`[${req.method}] ${req.path} Request:`, {
      body: req.body,
      query: req.query,
      params: req.params,
    });
  }

  next();
};

// Apply the debugging middleware
app.use(debugXendit);

// Test Xendit connection and verify API key
const testXenditConnection = async () => {
  try {
    console.log("Testing Xendit connection...");
    // Note: The original line `const eWalletTypes = await xendit.EWallet();` is not the standard way
    // to use xendit-node's EWallet service. It should be `await eWalletService.getEWallets();`
    // or similar if `eWalletService` is properly initialized and has such a method.
    // Keeping it as is for minimal changes to existing code outside the requested scope.
    const eWalletTypes = await xendit.EWallet(); // Change here
    console.log("Available e-wallet types:", eWalletTypes);

    console.log("Xendit connection successful!");
    return true;
  } catch (error) {
    console.error("Xendit connection failed:", error.message);
    return false;
  }
};

// Run the test on server startup
testXenditConnection().then((success) => {
  if (!success) {
    console.warn("WARNING: Xendit integration may not be properly configured!");
  }
});

// Transfer to another user with fixed fee structure (fee added to total)
app.post("/api/wallet/transfer", authenticateUser, async (req, res) => {
  try {
    const { recipientPhoneNumber, amount, description } = req.body;

    if (!recipientPhoneNumber || !amount || amount <= 0) {
      return res.status(400).json({ error: "Invalid input" });
    }

    // Temukan sender berdasarkan ID dari token (authenticateUser middleware)
    const sender = await prisma.user.findUnique({
      where: { id: req.user.id },
    });

    if (!sender) {
      return res.status(404).json({ error: "Sender not found" });
    }

    // Temukan recipient berdasarkan phoneNumber (gunakan findFirst karena bukan unique)
    const recipient = await prisma.user.findFirst({
      where: { phoneNumber: recipientPhoneNumber },
    });

    if (!recipient) {
      return res.status(404).json({ error: "Recipient not found" });
    }

    // Cek apakah pengirim mencoba mentransfer ke dirinya sendiri
    if (sender.id === recipient.id) {
      return res.status(400).json({ error: "You cannot transfer to yourself" });
    }

    // Hitung fee
    const fee = amount > 250000000 ? 10000 : 2500;
    const totalAmount = amount + fee;

    // Cek saldo cukup
    if (sender.balance < totalAmount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Eksekusi transaksi dalam satu prisma.$transaction agar atomic
    await prisma.$transaction(async (prismaTx) => {
      // Kurangi saldo sender
      await prismaTx.user.update({
        where: { id: sender.id },
        data: {
          balance: { decrement: totalAmount },
        },
      });

      // Tambah saldo recipient (tanpa fee)
      await prismaTx.user.update({
        where: { id: recipient.id },
        data: {
          balance: { increment: amount },
        },
      });

      // Catat transaksi fee
      await prismaTx.transaction.create({
        data: {
          userId: sender.id,
          type: "FEE",
          amount: fee,
          status: "COMPLETED",
          description: `Fee for transfer to ${recipient.phoneNumber}`,
        },
      });

      // Catat transaksi transfer
      await prismaTx.transaction.create({
        data: {
          userId: sender.id,
          recipientId: recipient.id,
          type: "TRANSFER",
          amount,
          status: "COMPLETED",
          description: description || `Transfer to ${recipient.phoneNumber}`,
        },
      });
    });

    // Response berhasil
    res.status(200).json({
      message: "Transfer completed successfully",
      data: {
        amount,
        fee,
        total: totalAmount,
        recipientName: recipient.name,
        recipientPhoneNumber: recipient.phoneNumber,
      },
    });
  } catch (error) {
    console.error("Transfer error:", error);
    res.status(500).json({ error: "Server error during transfer" });
  }
});

// Withdraw funds to bank account with fixed fee structure (fee added to total)
app.post("/api/wallet/withdraw", authenticateUser, async (req, res) => {
  try {
    const { amount, bankCode, accountNumber, accountHolderName } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: "Invalid amount" });
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
    });

    // Calculate fee based on amount
    let fee;
    if (amount > 250000000) {
      // More than 250 million
      fee = 10000;
    } else {
      fee = 2500;
    }

    const totalAmount = amount + fee;

    if (user.balance < totalAmount) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Create a reference ID for this withdrawal
    const referenceId = `withdraw-${user.id}-${Date.now()}`;

    // Send withdrawal to user's bank account via Xendit (full amount user requested)
    const disbursement = await disbursementService.create({
      externalID: referenceId,
      amount: amount, // User gets full amount they requested
      bankCode,
      accountHolderName,
      accountNumber,
      description: "E-wallet withdrawal",
    });

    // Process in transaction
    await prisma.$transaction(async (prismaClient) => {
      // Deduct total amount (amount + fee) from user balance
      await prismaClient.user.update({
        where: { id: user.id },
        data: {
          balance: {
            decrement: totalAmount,
          },
        },
      });

      // Record withdrawal transaction
      await prismaClient.transaction.create({
        data: {
          userId: user.id,
          type: "WITHDRAW",
          amount: amount,
          status: "PENDING",
          referenceId: disbursement.id,
          description: `Withdrawal to ${bankCode} - ${accountNumber}`,
        },
      });

      // Record fee transaction
      await prismaClient.transaction.create({
        data: {
          userId: user.id,
          type: "FEE",
          amount: fee,
          status: "COMPLETED",
          description: "Fee for withdrawal",
        },
      });
    });

    res.status(200).json({
      message: "Withdrawal initiated successfully",
      data: {
        withdrawalId: disbursement.id,
        amount: amount, // Amount user will receive
        fee,
        total: totalAmount, // Total deducted from balance
        status: "PENDING",
      },
    });
  } catch (error) {
    console.error("Withdrawal error:", error);
    res.status(500).json({ error: "Server error during withdrawal" });
  }
});

// Withdraw accumulated fees to admin account
app.post("/api/admin/withdraw-fees", authenticateUser, async (req, res) => {
  try {
    // Verify admin role (you should implement proper admin authorization)
    if (req.user.role !== "ADMIN") {
      return res.status(403).json({ error: "Access denied" });
    }

    // Get total accumulated fees (not yet withdrawn)
    const result = await prisma.$queryRaw`
      SELECT SUM(amount) as totalFees 
      FROM "Transaction" 
      WHERE type = 'FEE' AND status = 'COMPLETED' AND adminWithdrawn = false
    `;

    const totalFees = result?.totalFees || 0;

    if (totalFees <= 0) {
      return res.status(400).json({ error: "No fees available to withdraw" });
    }

    const { bankCode, accountNumber, accountHolderName } = req.body;

    // Create disbursement via Xendit
    const disbursement = await disbursementService.create({
      externalID: `admin-fee-${Date.now()}`,
      amount: totalFees,
      bankCode,
      accountHolderName,
      accountNumber,
      description: "Admin fee withdrawal",
    });

    // Mark fees as withdrawn
    await prisma.transaction.updateMany({
      where: {
        type: "FEE",
        status: "COMPLETED",
        adminWithdrawn: false,
      },
      data: {
        adminWithdrawn: true,
      },
    });

    res.status(200).json({
      message: "Admin fees withdrawal initiated successfully",
      data: {
        withdrawalId: disbursement.id,
        amount: totalFees,
        status: "PENDING",
      },
    });
  } catch (error) {
    console.error("Admin fee withdrawal error:", error);
    res.status(500).json({ error: "Server error during admin fee withdrawal" });
  }
});

// Get transaction history
app.get("/api/transactions", authenticateUser, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const skip = (page - 1) * limit;

    const where = {
      userId: req.user.id,
    };

    if (type) {
      where.type = type;
    }

    const transactions = await prisma.transaction.findMany({
      where,
      orderBy: {
        createdAt: "desc",
      },
      skip,
      take: Number(limit),
    });

    const total = await prisma.transaction.count({ where });

    res.status(200).json({
      message: "Transactions fetched successfully",
      data: {
        transactions,
        pagination: {
          total,
          page: Number(page),
          limit: Number(limit),
          totalPages: Math.ceil(total / limit),
        },
      },
    });
  } catch (error) {
    console.error("Transaction history error:", error);
    res.status(500).json({ error: "Server error while fetching transactions" });
  }
});

// Debug endpoint to check transaction status
app.get("/api/debug/transaction/:referenceId", async (req, res) => {
  try {
    const { referenceId } = req.params;

    const transaction = await prisma.transaction.findFirst({
      where: { referenceId },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            balance: true,
          },
        },
      },
    });

    if (!transaction) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    res.json({
      transaction,
      user: transaction.user,
    });
  } catch (error) {
    console.error("Debug endpoint error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Helper functions
function generateToken() {
  return require("crypto").randomBytes(32).toString("hex");
}

function hashPassword(password) {
  // In a real application, use bcrypt or similar
  return require("crypto").createHash("sha256").update(password).digest("hex");
}

app.listen(PORT, () => {
  console.log(`E-wallet service running on port http://localhost:${PORT}`);
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("SIGTERM received, shutting down...");
  await prisma.$disconnect();
  process.exit(0);
});
