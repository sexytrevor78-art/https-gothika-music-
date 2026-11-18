import express from "express";
import cors from "cors";
import { google } from "googleapis";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  `http://localhost:${PORT}/auth/youtube/callback`;
const ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;
const TOKEN_FILE = process.env.TOKEN_FILE || path.join(process.cwd(), "data", "youtube-token.enc");

const REQUIRED_ENV = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "TOKEN_ENCRYPTION_KEY"];
const missing = REQUIRED_ENV.filter((name) => !process.env[name]);
if (missing.length) {
  console.warn(`Missing environment variables: ${missing.join(", ")}`);
}

function getEncryptionKey() {
  if (!ENCRYPTION_KEY || !/^[a-fA-F0-9]{64}$/.test(ENCRYPTION_KEY)) {
    throw new Error("TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters (32 bytes).");
  }
  return Buffer.from(ENCRYPTION_KEY, "hex");
}

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

function decrypt(encoded) {
  const raw = Buffer.from(encoded, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const encrypted = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", getEncryptionKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

async function saveTokens(tokens) {
  await fs.mkdir(path.dirname(TOKEN_FILE), { recursive: true });
  await fs.writeFile(TOKEN_FILE, encrypt(JSON.stringify(tokens)), { mode: 0o600 });
}

async function loadTokens() {
  try {
    const encrypted = await fs.readFile(TOKEN_FILE, "utf8");
    return JSON.parse(decrypt(encrypted));
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function makeOAuthClient() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error("Google OAuth credentials are not configured.");
  }
  return new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
}

const pendingStates = new Map();

app.get("/", (_req, res) => {
  res.json({
    name: "Gothika",
    status: "online",
    message: "Gothika YouTube account-linking backend starter",
    routes: ["/health", "/auth/youtube", "/auth/youtube/callback", "/api/youtube/status", "/api/youtube/playlists", "/api/youtube/subscriptions"]
  });
});

app.get("/health", (_req, res) => res.json({ ok: true, service: "Gothika" }));

app.get("/auth/youtube", (_req, res) => {
  try {
    const oauth2 = makeOAuthClient();
    const state = crypto.randomBytes(24).toString("hex");
    pendingStates.set(state, Date.now());

    // Expire old one-time states.
    for (const [key, createdAt] of pendingStates) {
      if (Date.now() - createdAt > 10 * 60 * 1000) pendingStates.delete(key);
    }

    const url = oauth2.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: true,
      scope: ["https://www.googleapis.com/auth/youtube.readonly"],
      state
    });
    res.redirect(url);
  } catch (error) {
    res.status(500).send(`Gothika setup error: ${error.message}`);
  }
});

app.get("/auth/youtube/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send("Google sign-in was cancelled or denied.");
    if (!code || !state || !pendingStates.has(String(state))) {
      return res.status(400).send("Invalid or expired sign-in request. Please try again.");
    }
    pendingStates.delete(String(state));

    const oauth2 = makeOAuthClient();
    const { tokens } = await oauth2.getToken(String(code));
    const existing = await loadTokens().catch(() => null);
    const combined = {
      ...existing,
      ...tokens,
      refresh_token: tokens.refresh_token || existing?.refresh_token
    };
    await saveTokens(combined);

    res.send(`<!doctype html>
<html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gothika connected</title></head>
<body style="font-family:Arial,sans-serif;background:#111;color:#eee;padding:32px">
<h1>Gothika</h1><h2>YouTube account connected</h2>
<p>You can close this page and return to Gothika.</p></body></html>`);
  } catch (error) {
    console.error("YouTube OAuth callback failed:", error.message);
    res.status(500).send("Gothika could not finish connecting YouTube. Check the server logs and try again.");
  }
});

async function getYouTubeClient() {
  const tokens = await loadTokens();
  if (!tokens) {
    const error = new Error("No YouTube account is connected. Visit /auth/youtube first.");
    error.status = 401;
    throw error;
  }
  const oauth2 = makeOAuthClient();
  oauth2.setCredentials(tokens);
  oauth2.on("tokens", async (newTokens) => {
    try {
      await saveTokens({ ...tokens, ...newTokens });
    } catch (error) {
      console.error("Could not refresh encrypted YouTube tokens:", error.message);
    }
  });
  return google.youtube({ version: "v3", auth: oauth2 });
}

app.get("/api/youtube/status", async (_req, res) => {
  try {
    const youtube = await getYouTubeClient();
    const response = await youtube.channels.list({ part: ["snippet"], mine: true });
    const channel = response.data.items?.[0];
    res.json({
      connected: true,
      channel: channel ? {
        title: channel.snippet?.title || "",
        thumbnail: channel.snippet?.thumbnails?.default?.url || ""
      } : null
    });
  } catch (error) {
    res.status(error.status || 500).json({ connected: false, error: error.message });
  }
});

app.get("/api/youtube/playlists", async (req, res) => {
  try {
    const youtube = await getYouTubeClient();
    const response = await youtube.playlists.list({
      part: ["snippet", "contentDetails"],
      mine: true,
      maxResults: Math.min(Number(req.query.maxResults) || 50, 50),
      pageToken: req.query.pageToken || undefined
    });
    res.json({
      items: (response.data.items || []).map((item) => ({
        id: item.id,
        title: item.snippet?.title || "",
        description: item.snippet?.description || "",
        thumbnail: item.snippet?.thumbnails?.medium?.url || "",
        videoCount: item.contentDetails?.itemCount || 0
      })),
      nextPageToken: response.data.nextPageToken || null
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.get("/api/youtube/subscriptions", async (req, res) => {
  try {
    const youtube = await getYouTubeClient();
    const response = await youtube.subscriptions.list({
      part: ["snippet"],
      mine: true,
      maxResults: Math.min(Number(req.query.maxResults) || 50, 50),
      pageToken: req.query.pageToken || undefined
    });
    res.json({
      items: (response.data.items || []).map((item) => ({
        channelId: item.snippet?.resourceId?.channelId || "",
        title: item.snippet?.title || "",
        description: item.snippet?.description || "",
        thumbnail: item.snippet?.thumbnails?.medium?.url || ""
      })),
      nextPageToken: response.data.nextPageToken || null
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
});

app.post("/api/youtube/disconnect", async (_req, res) => {
  try {
    await fs.unlink(TOKEN_FILE);
    res.json({ disconnected: true });
  } catch (error) {
    if (error.code === "ENOENT") return res.json({ disconnected: true });
    res.status(500).json({ error: "Could not remove the saved YouTube connection." });
  }
});

app.listen(PORT, () => {
  console.log(`Gothika running on port ${PORT}`);
});
