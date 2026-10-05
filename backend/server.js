/* ==========================================================================
   server.js
   FinTack API entry point.

   Route handlers live in ./routes. This file only wires middleware,
   mounts routers and starts the listener.
========================================================================== */

const express = require("express");
const cors = require("cors");

const env = require("./config/env");
const supabase = require("./config/supabase");

const { rateLimit } = require("./middleware/rateLimit");
const { notFound, errorHandler } = require("./middleware/errorHandler");

const authRoutes = require("./routes/auth");
const transactionRoutes = require("./routes/transactions");
const goalRoutes = require("./routes/goals");
const tripRoutes = require("./routes/trips");
const aiRoutes = require("./routes/ai");
const newsRoutes = require("./routes/news");
const agentRoutes = require("./routes/agent");
const { router: assetRoutes, TYPES: ASSET_TYPES } = require("./routes/assets");

const app = express();

/* ==========================================================
                        CORE MIDDLEWARE
========================================================== */

app.set("trust proxy", 1);

/*
    CORS is no longer a blanket "*" in production - set CORS_ORIGINS to a
    comma separated allowlist of your deployed frontend origins.
*/
const allowedOrigins = env.CORS_ORIGINS
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

app.use(cors({
    origin(origin, callback) {
        if (allowedOrigins.includes("*") || !origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        return callback(new Error(`Origin not allowed by CORS: ${origin}`));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true, limit: "256kb" }));

/* Minimal security headers without pulling in helmet. */
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-XSS-Protection", "0");
    next();
});

/* Blanket limiter - individual auth routes apply stricter limits. */
app.use(rateLimit({
    windowMs: 60 * 1000,
    max: 240,
    key: "global",
    byEmail: false
}));

/* ==========================================================
                        HEALTH
========================================================== */

app.get("/", (req, res) => {
    res.json({
        status: "FinTack Backend Running",
        version: "2.0.0",
        environment: env.NODE_ENV,
        docs: "/api/docs"
    });
});

app.get("/health", async (req, res) => {
    let database = "unknown";

    try {
        const { error } = await supabase
            .from("users")
            .select("id", { head: true, count: "exact" })
            .limit(1);

        database = error ? "error" : "ok";
    } catch (err) {
        database = "error";
    }

    res.json({
        success: database === "ok",
        uptimeSeconds: Math.round(process.uptime()),
        database,
        mail: env.smtpConfigured ? "smtp" : "console",
        ai: env.GEMINI_API_KEY ? "configured" : "not configured"
    });
});

app.get("/api/docs", (req, res) => {
    res.json({
        success: true,
        message: "See API.md in the repository root for the full reference.",
        groups: {
            auth: [
                "POST /auth/signup",
                "POST /auth/login",
                "GET  /auth/me",
                "POST /auth/forgot-password",
                "POST /auth/verify-otp",
                "POST /auth/reset-password",
                "POST /auth/change-password"
            ],
            assets: [
                "GET    /api/assets/:userId",
                "POST   /api/assets",
                "PUT    /api/assets/:id",
                "DELETE /api/assets/:id"
            ],
            transactions: [
                "GET    /api/transactions/:userId",
                "GET    /api/transactions/:userId/analytics",
                "GET    /api/transactions/detail/:id",
                "POST   /api/transactions",
                "PUT    /api/transactions/:id",
                "DELETE /api/transactions/:id"
            ],
            goals: [
                "GET    /api/goals/:userId",
                "POST   /api/goals",
                "PUT    /api/goals/:id",
                "PUT    /api/goals/:id/savings",
                "DELETE /api/goals/:id",
                "POST   /api/goals/:id/investment-plan"
            ],
            ai: [
                "POST /api/ai/ask",
                "POST /api/ai/chats",
                "GET  /api/ai/chats",
                "GET  /api/ai/chats/:id/messages",
                "POST /api/ai/chats/:id/messages",
                "DELETE /api/ai/chats/:id"
            ],
            agent: [
                "POST /api/agent/ask",
                "GET  /api/agent/health"
            ]
        }
    });
});

/* ==========================================================
                        ROUTES
========================================================== */

app.use("/auth", authRoutes);

/*
    The original frontend posted to /login and /signup at the root.
    Keep those working so nothing breaks mid-deploy.
*/
app.use("/", authRoutes);

app.use("/api/transactions", transactionRoutes);
app.use("/api/assets", assetRoutes);
app.use("/api/goals", goalRoutes);
app.use("/api/trips", tripRoutes);
app.use("/api/ai", aiRoutes);
app.use("/api/news", newsRoutes);
app.use("/api/agent", agentRoutes);

/* ==========================================================
                    DASHBOARD (derived, not hardcoded)
========================================================== */

const { requireAuth } = require("./middleware/auth");
const { buildSummary } = require("./utils/analytics");
const { decryptRow } = require("./utils/crypto");

app.get("/api/dashboard", requireAuth, async (req, res, next) => {
    try {
        const [{ data: user }, { data: transactions }, { data: goals }, { data: assets }] =
            await Promise.all([
                supabase
                    .from("users")
                    .select("id, full_name, email, created_at")
                    .eq("id", req.user.id)
                    .maybeSingle(),

                supabase
                    .from("transactions")
                    .select("id, user_id, encrypted_payload, title, description, amount, type, category, date, created_at, updated_at")
                    .eq("user_id", req.user.id)
                    .limit(10000),

                supabase
                    .from("goals")
                    .select("id, user_id, encrypted_payload, title, target_amount, saved_amount, deadline, risk_tolerance, created_at, updated_at")
                    .eq("user_id", req.user.id),

                supabase
                    .from("assets")
                    .select("id, user_id, encrypted_payload, created_at, updated_at")
                    .eq("user_id", req.user.id)
            ]);

        const decryptedTransactions = (transactions || []).map(row => decryptRow(row, [
            "title", "description", "amount", "type", "category", "date"
        ])).filter(Boolean);
        const decryptedGoals = (goals || []).map(row => decryptRow(row, [
            "title", "target_amount", "saved_amount", "deadline", "risk_tolerance"
        ])).filter(Boolean);
        const decryptedAssets = (assets || []).map(row => decryptRow(row)).filter(Boolean);
        const totalAssetValue = decryptedAssets.reduce(
            (sum, asset) => sum + (Number(asset?.value) || 0),
            0
        );

        decryptedTransactions.sort((a, b) => new Date(b.date || b.created_at) - new Date(a.date || a.created_at));
        const summary = buildSummary(decryptedTransactions);
        summary.netWorth = (Number(summary.netWorth) || 0) + totalAssetValue;
        summary.totalNetWorth = summary.netWorth;
        summary.assetValue = totalAssetValue;

        return res.json({
            success: true,
            user,
            summary,
            goals: decryptedGoals,
            recentTransactions: decryptedTransactions.slice(0, 10)
        });
    } catch (err) {
        return next(err);
    }
});

/* ==========================================================
                    ERROR HANDLING
========================================================== */

app.use(notFound);
app.use(errorHandler);

/* ==========================================================
                        START
========================================================== */

const PORT = Number(process.env.PORT) || env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`FinTack API running on port ${PORT}`);
    console.log(`   env:  ${env.NODE_ENV}`);
    console.log(`   mail: ${env.smtpConfigured ? "SMTP" : "console fallback"}`);
    console.log(`   ai:   ${env.GEMINI_API_KEY ? "Gemini enabled" : "Gemini disabled"}`);
});


module.exports = app;