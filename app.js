import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcrypt";
import { fileURLToPath } from "url";
import { dirname } from "path";
import { users } from "./auth/users.js";
import { setup2FA, verify2FA } from "./auth/twofa.js";
import path from "path";
import cors from "cors";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

app.use(
  cors({
    origin: ["http://localhost:8080", "http://localhost:3000"],
  })
);

app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: false,
    cookie: {
      sameSite: "lax",
      secure: false, // set to true if using HTTPS
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Passport setup
passport.use(
  new LocalStrategy((username, password, done) => {
    const user = users.find((user) => user.username === username);
    if (!user) return done(null, false);
    bcrypt.compare(password, user.passwordHash).then((isMatch) => {
      if (!isMatch) return done(null, false);
      return done(null, user);
    });
  })
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = users.find((user) => user.id === id);
  done(null, user);
});

// Routes
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const id = Date.now().toString();
  const passwordHash = await bcrypt.hash(password, 10);
  const { otpauth_url, base32 } = setup2FA();
  users.push({
    id,
    username,
    passwordHash,
    twoFASecret: base32,
    is2FAEnabled: true,
  });

  res.json({ qrUrl: otpauth_url });
});

app.post("/login", passport.authenticate("local"), (req, res) => {
  if (req.user.is2FAEnabled) {
    req.session.tempUserId = req.user.id;
    req.logout((err) => {
      if (err) console.log(err);
    });
    return res.json({ message: "2FA required" });
  }
  res.json({ message: "Logged in without 2FA" });
});

app.post("/verify-2fa", (req, res) => {
  const user = users.find((u) => u.id === req.session.tempUserId);
  console.log("🧠 Session:", req.session);
  if (!user) return res.status(401).json({ message: "Unauthorized" });
  console.log("🧠 Session:", req.session);

  const isValid = verify2FA(user.twoFASecret, req.body.token);
  console.log("🧠 Session:", req.session);
  if (!isValid) return res.status(401).json({ message: "Invalid 2FA code" });
  console.log("🧠 Session:", req.session);

  req.login(user, (err) => {
    if (err) return res.status(500).json({ message: "Login failed" });
    delete req.session.tempUserId;
    return res.json({ message: "2FA login successful" });
  });
});

const PORT = 8080;
app.listen(PORT, () => {
  console.log("App is running on PORT: ", PORT);
});
