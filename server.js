require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");
app.use(helmet());

app.use(express.json({ limit: "50kb" }));

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
  })
);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "development-only-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ossper-markets",
    virtualMoneyOnly: true
  });
});

app.use(express.static(path.join(__dirname)));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Ossper Markets listening on port ${PORT}`);
});
