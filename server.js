require("dotenv").config();
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(express.json({limit:"50kb"}));
app.use(rateLimit({windowMs: 15*60*1000, max: 200}));
app.use(session({
  secret: process.env.SESSION_SECRET || "LOCAL_DEMO_ONLY_CHANGE_ME",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
}));

app.get("/api/health", (_req,res)=>res.json({ok:true, service:"ossper-markets"}));
app.get("/", (_req,res)=>res.sendFile(__dirname + "/index.html"));

app.listen(PORT, ()=>console.log(`Ossper running on port ${PORT}`));
