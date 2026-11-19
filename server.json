
import express from "express";
import cors from "cors";
import { google } from "googleapis";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const app = express();

app.set("trust proxy", 1);
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  `http://localhost:${PORT}/auth/youtube/callback`;

const ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY;

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(process.cwd(), "data", "youtube-token.enc");

const SUPABASE_URL = process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const SUPABASE_TABLE =
  process.env.SUPABASE_TABLE || "gothika_tokens";

const LEGACY_ACCOUNT_ID = "youtube";

const WEB_SESSION_COOKIE = "gothika_web_session";
const WEB_SESSION_DAYS = 30;

const missing = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "TOKEN_ENCRYPTION_KEY",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY"
].filter(name => !process.env[name]);

if (missing.length) {
  console.warn(
    "Missing environment variables:",
    missing.join(", ")
  );
}

// ACCOUNT HELPERS

function validAccountId(id) {
  return (
    id === LEGACY_ACCOUNT_ID ||
    (
      typeof id === "string" &&
      /^[a-f0-9]{64}$/i.test(id)
    )
  );
}

function accountIdFromRequest(req) {
  const id = req.params.userId;

  if (!validAccountId(id)) {
    const error = new Error(
      "Invalid Gothika account link."
    );

    error.status = 400;
    throw error;
  }

  return id;
}

function requireUserId(req, res, next) {
  try {
    accountIdFromRequest(req);
    next();
  } catch (error) {
    res.status(error.status || 400).json({
      error: error.message
    });
  }
}

function createAccountId() {
  return crypto.randomBytes(32).toString("hex");
}

// ENCRYPTION

function getEncryptionKey() {
  if (
    !ENCRYPTION_KEY ||
    !/^[a-fA-F0-9]{64}$/.test(ENCRYPTION_KEY)
  ) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters."
    );
  }

  return Buffer.from(ENCRYPTION_KEY, "hex");
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  return Buffer.concat([
    iv,
    cipher.getAuthTag(),
    encrypted
  ]).toString("base64");
}

function decrypt(encoded) {
  const raw = Buffer.from(encoded, "base64");

  if (raw.length < 29) {
    throw new Error("Stored token data is invalid.");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    raw.subarray(0, 12)
  );

  decipher.setAuthTag(raw.subarray(12, 28));

  return Buffer.concat([
    decipher.update(raw.subarray(28)),
    decipher.final()
  ]).toString("utf8");
}

// SUPABASE TOKEN STORAGE

function supabaseEndpoint() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error(
      "Supabase credentials are missing."
    );
  }

  return (
    SUPABASE_URL.replace(/\/$/, "") +
    "/rest/v1/" +
    encodeURIComponent(SUPABASE_TABLE)
  );
}

async function saveTokens(accountId, tokens) {
  const url = new URL(supabaseEndpoint());

  url.searchParams.set("on_conflict", "id");

  const response = await fetch(url, {
    method: "POST",

    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization:
        `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer:
        "resolution=merge-duplicates,return=minimal"
    },

    body: JSON.stringify({
      id: accountId,
      encrypted_token: encrypt(
        JSON.stringify(tokens)
      ),
      updated_at: new Date().toISOString()
    })
  });

  if (!response.ok) {
    throw new Error(
      `Supabase save failed (${response.status}): ${await response.text()}`
    );
  }
}

async function readLegacyTokenFile() {
  try {
    const encoded = await fs.readFile(
      TOKEN_FILE,
      "utf8"
    );

    return JSON.parse(decrypt(encoded));

  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function loadTokens(accountId) {
  const url = new URL(supabaseEndpoint());

  url.searchParams.set("select", "encrypted_token");
  url.searchParams.set("id", `eq.${accountId}`);
  url.searchParams.set("limit", "1");

  const response = await fetch(url, {
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization:
        `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    }
  });

  if (!response.ok) {
    throw new Error(
      `Supabase read failed (${response.status}): ${await response.text()}`
    );
  }

  const rows = await response.json();

  if (rows.length && rows[0].encrypted_token) {
    return JSON.parse(
      decrypt(rows[0].encrypted_token)
    );
  }

  if (accountId === LEGACY_ACCOUNT_ID) {
    const oldTokens = await readLegacyTokenFile();

    if (oldTokens) {
      await saveTokens(accountId, oldTokens);
      return oldTokens;
    }
  }

  return null;
}

async function deleteTokens(accountId) {
  const url = new URL(supabaseEndpoint());

  url.searchParams.set("id", `eq.${accountId}`);

  const response = await fetch(url, {
    method: "DELETE",

    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization:
        `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    }
  });

  if (!response.ok) {
    throw new Error(
      `Supabase delete failed (${response.status}): ${await response.text()}`
    );
  }

  if (accountId === LEGACY_ACCOUNT_ID) {
    try {
      await fs.unlink(TOKEN_FILE);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

// PART 2: GOOGLE SIGN-IN AND YOUTUBE FUNCTIONS

const pendingStates = new Map();

function makeOAuthClient() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI
  );
}

function publicBaseUrl(req) {
  return (
    process.env.PUBLIC_BASE_URL ||
    `${req.protocol}://${req.get("host")}`
  ).replace(/\/$/, "");
}

function cleanPendingStates() {
  const now = Date.now();

  for (const [state, data] of pendingStates.entries()) {
    if (now - data.createdAt > 10 * 60 * 1000) {
      pendingStates.delete(state);
    }
  }
}

function startGoogleSignIn(req, res) {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REDIRECT_URI) {
    return res.status(500).send("Google sign-in is not configured.");
  }

  cleanPendingStates();

  const state = crypto.randomBytes(32).toString("hex");
  const accountId = crypto.randomBytes(32).toString("hex");

  pendingStates.set(state, {
    accountId,
    createdAt: Date.now()
  });

  const oauth2Client = makeOAuthClient();

  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/youtube.readonly"
    ],
    state
  });

  res.redirect(url);
}

app.get("/auth/youtube", startGoogleSignIn);
app.get("/auth/youtube/legacy", startGoogleSignIn);

function successPage(accountId, baseUrl) {
  const manifestUrl =
    `${baseUrl}/u/${accountId}/manifest.json`;

  return `<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gothika Connected</title>
<style>
body {
  background: #100b12;
  color: #eee;
  font-family: Arial, sans-serif;
  text-align: center;
  padding: 50px 18px;
}
.box {
  max-width: 600px;
  margin: auto;
  background: #211522;
  padding: 25px;
  border-radius: 14px;
}
input {
  width: 95%;
  padding: 12px;
  margin: 15px 0;
  background: #100b12;
  color: white;
  border: 1px solid #70416f;
  border-radius: 6px;
}
button {
  padding: 12px 20px;
  background: #743c78;
  color: white;
  border: 0;
  border-radius: 6px;
  cursor: pointer;
}
</style>
</head>
<body>
<div class="box">
<h1>Gothika</h1>
<h2>YouTube Connected</h2>
<p>Your Google account has been connected successfully.</p>
<p>Your personal Stremio manifest URL:</p>
<input id="manifest" readonly value="${manifestUrl}">
<button onclick="copyManifest()">Copy Manifest URL</button>
<p>You can use this private URL in your Stremio add-on.</p>
</div>
<script>
function copyManifest() {
  const input = document.getElementById("manifest");
  input.select();
  navigator.clipboard.writeText(input.value);
  alert("Manifest URL copied.");
}
</script>
</body>
</html>`;
}

app.get("/auth/youtube/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send("Google sign-in was cancelled.");
    }

    if (!code || !state || !pendingStates.has(state)) {
      return res.status(400).send("Invalid or expired sign-in request.");
    }

    const pending = pendingStates.get(state);
    pendingStates.delete(state);

    const oauth2Client = makeOAuthClient();

    const { tokens } = await oauth2Client.getToken(code);

    if (!tokens.access_token) {
      return res.status(400).send("Google did not return an access token.");
    }

    await saveTokens(pending.accountId, tokens);

    res.set("Cache-Control", "no-store");

    return res.send(
      successPage(pending.accountId, publicBaseUrl(req))
    );
  } catch (error) {
    console.error("YouTube OAuth callback error:", error);
    return res.status(500).send("Unable to connect your YouTube account.");
  }
});

async function getYouTubeClient(accountId) {
  const tokens = await loadTokens(accountId);

  if (!tokens) {
    throw new Error("YouTube account is not connected.");
  }

  const oauth2Client = makeOAuthClient();
  oauth2Client.setCredentials(tokens);

  oauth2Client.on("tokens", async (newTokens) => {
    try {
      const updated = { ...tokens, ...newTokens };
      await saveTokens(accountId, updated);
    } catch (error) {
      console.error("Token refresh save error:", error);
    }
  });

  return google.youtube({
    version: "v3",
    auth: oauth2Client
  });
}

function imageOf(thumbnails) {
  if (!thumbnails) return "";

  return (
    thumbnails.maxres?.url ||
    thumbnails.high?.url ||
    thumbnails.medium?.url ||
    thumbnails.default?.url ||
    ""
  );
}

function videoMeta(video) {
  const snippet = video.snippet || {};
  const videoId = video.id?.videoId || video.id;

  return {
    id: `ytvideo:${videoId}`,
    type: "movie",
    name: snippet.title || "YouTube Video",
    poster: imageOf(snippet.thumbnails),
    background: imageOf(snippet.thumbnails),
    description: snippet.description || "",
    releaseInfo: snippet.publishedAt
      ? snippet.publishedAt.slice(0, 10)
      : ""
  };
}

function playlistMeta(playlist) {
  const snippet = playlist.snippet || {};

  return {
    id: `ytplaylist:${playlist.id}`,
    type: "series",
    name: snippet.title || "YouTube Playlist",
    poster: imageOf(snippet.thumbnails),
    background: imageOf(snippet.thumbnails),
    description: snippet.description || ""
  };
}

function channelMeta(channel) {
  const snippet = channel.snippet || {};

  return {
    id: `ytchannel:${channel.id}`,
    type: "channel",
    name: snippet.title || "YouTube Channel",
    poster: imageOf(snippet.thumbnails),
    background: imageOf(snippet.thumbnails),
    description: snippet.description || ""
  };
}

async function getPlaylistItems(youtube, playlistId, maxResults = 50) {
  const response = await youtube.playlistItems.list({
    part: "snippet,contentDetails",
    playlistId,
    maxResults
  });

  return (response.data.items || [])
    .filter(item => item.contentDetails?.videoId)
    .map(item => ({
      id: `ytvideo:${item.contentDetails.videoId}`,
      type: "movie",
      name: item.snippet?.title || "YouTube Video",
      poster: imageOf(item.snippet?.thumbnails),
      background: imageOf(item.snippet?.thumbnails),
      description: item.snippet?.description || ""
    }));
}

async function getChannelUploadsPlaylist(youtube, channelId) {
  const response = await youtube.channels.list({
    part: "contentDetails",
    id: channelId
  });

  return response.data.items?.[0]
    ?.contentDetails?.relatedPlaylists?.uploads || null;
}

async function getLikedVideos(youtube) {
  const response = await youtube.videos.list({
    part: "snippet,contentDetails",
    myRating: "like",
    maxResults: 50
  });

  return (response.data.items || []).map(videoMeta);
}

async function searchYouTube(youtube, query, music = false) {
  const response = await youtube.search.list({
    part: "snippet",
    q: query,
    type: "video",
    videoCategoryId: music ? "10" : undefined,
    maxResults: 30,
    safeSearch: "none"
  });

  return (response.data.items || []).map(videoMeta);
}

function createManifest(accountId) {
  return {
    id: "com.gothika.youtube",
    version: "1.0.0",
    name: "Gothika",
    description: "Your personal YouTube library and music in Stremio.",
    logo: "",
    resources: ["catalog", "meta", "stream"],
    types: ["movie", "series", "channel"],
    idPrefixes: ["ytvideo:", "ytplaylist:", "ytchannel:"],
    catalogs: [
      {
        type: "series",
        id: "youtube_playlists",
        name: "My YouTube Playlists"
      },
      {
        type: "movie",
        id: "youtube_liked",
        name: "My Liked Videos"
      },
      {
        type: "channel",
        id: "youtube_subscriptions",
        name: "My Subscriptions"
      },
      {
        type: "movie",
        id: "youtube_search",
        name: "Search YouTube",
        extra: [{ name: "search", isRequired: false }]
      },
      {
        type: "movie",
        id: "youtube_music_search",
        name: "Search YouTube Music",
        extra: [{ name: "search", isRequired: false }]
      },
      {
        type: "movie",
        id: "youtube_trending",
        name: "YouTube Videos"
      }
    ]
  };
}

// END PART 2

// PART 3: STREMIO ADD-ON ROUTES

async function catalogueHandler(req, res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);
    const catalogId = req.params.catalogId;
    const search = String(req.query.search || "").trim();

    let metas = [];

    if (catalogId === "youtube_playlists") {
      const response = await youtube.playlists.list({
        part: "snippet,contentDetails",
        mine: true,
        maxResults: 50
      });

      metas = (response.data.items || []).map(playlistMeta);

    } else if (catalogId === "youtube_liked") {
      metas = await getLikedVideos(youtube);

    } else if (catalogId === "youtube_subscriptions") {
      const response = await youtube.subscriptions.list({
        part: "snippet",
        mine: true,
        maxResults: 50
      });

      metas = (response.data.items || []).map(item =>
        channelMeta(item.snippet?.resourceId?.channelId
          ? {
              id: item.snippet.resourceId.channelId,
              snippet: item.snippet
            }
          : item)
      );

    } else if (catalogId === "youtube_search") {
      if (search) {
        metas = await searchYouTube(youtube, search, false);
      }

    } else if (catalogId === "youtube_music_search") {
      if (search) {
        metas = await searchYouTube(youtube, search, true);
      }

    } else if (catalogId === "youtube_trending") {
      const response = await youtube.videos.list({
        part: "snippet,contentDetails",
        chart: "mostPopular",
        regionCode: "US",
        maxResults: 30
      });

      metas = (response.data.items || []).map(videoMeta);
    }

    res.json({ metas });
  } catch (error) {
    console.error("Catalogue error:", error);
    res.status(500).json({
      metas: [],
      error: "Unable to load YouTube catalogue."
    });
  }
}

async function metadataHandler(req, res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);
    const id = req.params.id;

    if (id.startsWith("ytvideo:")) {
      const videoId = id.replace("ytvideo:", "");

      const response = await youtube.videos.list({
        part: "snippet,contentDetails",
        id: videoId
      });

      const video = response.data.items?.[0];

      if (!video) {
        return res.status(404).json({ meta: null });
      }

      return res.json({ meta: videoMeta(video) });
    }

    if (id.startsWith("ytplaylist:")) {
      const playlistId = id.replace("ytplaylist:", "");

      const response = await youtube.playlists.list({
        part: "snippet,contentDetails",
        id: playlistId
      });

      const playlist = response.data.items?.[0];

      if (!playlist) {
        return res.status(404).json({ meta: null });
      }

      return res.json({ meta: playlistMeta(playlist) });
    }

    if (id.startsWith("ytchannel:")) {
      const channelId = id.replace("ytchannel:", "");

      const response = await youtube.channels.list({
        part: "snippet",
        id: channelId
      });

      const channel = response.data.items?.[0];

      if (!channel) {
        return res.status(404).json({ meta: null });
      }

      return res.json({ meta: channelMeta(channel) });
    }

    res.status(404).json({ meta: null });
  } catch (error) {
    console.error("Metadata error:", error);
    res.status(500).json({ meta: null });
  }
}

async function streamHandler(req, res) {
  const id = req.params.id;

  if (!id.startsWith("ytvideo:")) {
    return res.json({ streams: [] });
  }

  const videoId = id.replace("ytvideo:", "");

  res.json({
    streams: [
      {
        name: "Gothika",
        title: "▶ Play on YouTube",
        externalUrl: `https://www.youtube.com/watch?v=${encodeURIComponent(videoId)}`
      }
    ]
  });
}

// LEGACY STREMIO ROUTES

app.get("/manifest.json", (req, res) => {
  res.json(createManifest(LEGACY_ACCOUNT_ID));
});

app.get("/catalog/:type/:catalogId.json", (req, res) => {
  catalogueHandler(req, res, LEGACY_ACCOUNT_ID);
});

app.get("/meta/:type/:id.json", (req, res) => {
  metadataHandler(req, res, LEGACY_ACCOUNT_ID);
});

app.get("/stream/:type/:id.json", streamHandler);

// PERSONAL STREMIO ROUTES

app.get("/u/:userId/manifest.json", (req, res) => {
  const accountId = req.params.userId;

  if (!/^[a-f0-9]{64}$/i.test(accountId)) {
    return res.status(400).json({ error: "Invalid Gothika account link." });
  }

  res.json(createManifest(accountId));
});

app.get("/u/:userId/catalog/:type/:catalogId.json", (req, res) => {
  const accountId = req.params.userId;

  if (!/^[a-f0-9]{64}$/i.test(accountId)) {
    return res.status(400).json({ metas: [] });
  }

  catalogueHandler(req, res, accountId);
});

app.get("/u/:userId/meta/:type/:id.json", (req, res) => {
  const accountId = req.params.userId;

  if (!/^[a-f0-9]{64}$/i.test(accountId)) {
    return res.status(400).json({ meta: null });
  }

  metadataHandler(req, res, accountId);
});

app.get("/u/:userId/stream/:type/:id.json", (req, res) => {
  const accountId = req.params.userId;

  if (!/^[a-f0-9]{64}$/i.test(accountId)) {
    return res.status(400).json({ streams: [] });
  }

  streamHandler(req, res);
});

// ACCOUNT STATUS

app.get("/u/:userId/api/youtube/status", async (req, res) => {
  try {
    const accountId = req.params.userId;

    if (!/^[a-f0-9]{64}$/i.test(accountId)) {
      return res.status(400).json({ connected: false });
    }

    const tokens = await loadTokens(accountId);

    res.json({
      connected: Boolean(tokens),
      accountId
    });
  } catch (error) {
    console.error("Account status error:", error);
    res.status(500).json({ connected: false });
  }
});

// PLAYLISTS API

app.get("/u/:userId/api/youtube/playlists", async (req, res) => {
  try {
    const youtube = await getYouTubeClient(req.params.userId);

    const response = await youtube.playlists.list({
      part: "snippet,contentDetails",
      mine: true,
      maxResults: 50
    });

    res.json({
      items: response.data.items || []
    });
  } catch (error) {
    console.error("Playlists API error:", error);
    res.status(500).json({ items: [] });
  }
});

// SUBSCRIPTIONS API

app.get("/u/:userId/api/youtube/subscriptions", async (req, res) => {
  try {
    const youtube = await getYouTubeClient(req.params.userId);

    const response = await youtube.subscriptions.list({
      part: "snippet",
      mine: true,
      maxResults: 50
    });

    res.json({
      items: response.data.items || []
    });
  } catch (error) {
    console.error("Subscriptions API error:", error);
    res.status(500).json({ items: [] });
  }
});

// DISCONNECT YOUTUBE ACCOUNT

app.post("/u/:userId/api/youtube/disconnect", async (req, res) => {
  try {
    const accountId = req.params.userId;

    if (!/^[a-f0-9]{64}$/i.test(accountId)) {
      return res.status(400).json({ error: "Invalid account ID." });
    }

    await deleteTokens(accountId);

    res.json({ success: true });
  } catch (error) {
    console.error("Disconnect error:", error);
    res.status(500).json({ error: "Unable to disconnect account." });
  }
});

// END PART 3

// PART 4: GOTHIKA WEB PLAYER

function signWebSession(accountId) {
  const signature = crypto
    .createHmac("sha256", TOKEN_ENCRYPTION_KEY)
    .update(accountId)
    .digest("hex");

  return `${accountId}.${signature}`;
}

function verifyWebSession(token) {
  if (!token || typeof token !== "string") return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [accountId, signature] = parts;

  if (!/^[a-f0-9]{64}$/i.test(accountId)) return null;

  const expected = crypto
    .createHmac("sha256", TOKEN_ENCRYPTION_KEY)
    .update(accountId)
    .digest("hex");

  const suppliedBuffer = Buffer.from(signature, "hex");
  const expectedBuffer = Buffer.from(expected, "hex");

  if (
    suppliedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(suppliedBuffer, expectedBuffer)
  ) {
    return null;
  }

  return accountId;
}

function getCookie(req, name) {
  const cookies = String(req.headers.cookie || "")
    .split(";");

  for (const cookie of cookies) {
    const separator = cookie.indexOf("=");

    if (separator === -1) continue;

    const key = cookie.slice(0, separator).trim();
    const value = cookie.slice(separator + 1).trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function requireWebSession(req, res, next) {
  const token = getCookie(req, "gothika_session");
  const accountId = verifyWebSession(token);

  if (!accountId) {
    return res.status(401).json({
      error: "Please connect your YouTube account."
    });
  }

  req.webAccountId = accountId;
  next();
}

// CONNECT WEB PLAYER TO PERSONAL MANIFEST

app.post("/api/web/connect", async (req, res) => {
  try {
    const manifestUrl = String(req.body?.manifestUrl || "").trim();

    if (!manifestUrl) {
      return res.status(400).json({
        error: "Enter your personal Gothika manifest URL."
      });
    }

    let parsed;

    try {
      parsed = new URL(manifestUrl);
    } catch {
      return res.status(400).json({
        error: "That manifest URL is not valid."
      });
    }

    const baseUrl = publicBaseUrl(req);

    if (
      parsed.origin !== baseUrl ||
      parsed.search ||
      parsed.hash
    ) {
      return res.status(400).json({
        error: "Use your personal Gothika manifest URL from this server."
      });
    }

    const match = parsed.pathname.match(
      /^\/u\/([a-f0-9]{64})\/manifest\.json$/i
    );

    if (!match) {
      return res.status(400).json({
        error: "Invalid Gothika account link."
      });
    }

    const accountId = match[1];

    const tokens = await loadTokens(accountId);

    if (!tokens) {
      return res.status(401).json({
        error: "This YouTube account is not connected."
      });
    }

    // Confirm that the saved account can access YouTube.
    const youtube = await getYouTubeClient(accountId);

    await youtube.channels.list({
      part: "id",
      mine: true
    });

    const session = signWebSession(accountId);

    res.cookie("gothika_session", session, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      message: "YouTube connected successfully."
    });
  } catch (error) {
    console.error("Web connect error:", error);

    res.status(500).json({
      error: "Unable to connect your YouTube account."
    });
  }
});

// CHECK WEB PLAYER SESSION

app.get("/api/web/session", requireWebSession, async (req, res) => {
  try {
    const tokens = await loadTokens(req.webAccountId);

    if (!tokens) {
      return res.status(401).json({
        connected: false
      });
    }

    res.json({
      connected: true
    });
  } catch (error) {
    console.error("Web session error:", error);

    res.status(500).json({
      connected: false
    });
  }
});

// WEB PLAYER CATALOGUES

app.get(
  "/api/web/catalog/:catalogId",
  requireWebSession,
  async (req, res) => {
    try {
      const youtube = await getYouTubeClient(req.webAccountId);
      const catalogId = req.params.catalogId;
      const search = String(req.query.search || "").trim();

      let items = [];

      if (catalogId === "youtube_playlists") {
        const response = await youtube.playlists.list({
          part: "snippet,contentDetails",
          mine: true,
          maxResults: 50
        });

        items = (response.data.items || []).map(playlistMeta);

      } else if (catalogId === "youtube_liked") {
        items = await getLikedVideos(youtube);

      } else if (catalogId === "youtube_subscriptions") {
        const response = await youtube.subscriptions.list({
          part: "snippet",
          mine: true,
          maxResults: 50
        });

        items = (response.data.items || []).map(item => ({
          id: `ytchannel:${item.snippet.resourceId.channelId}`,
          type: "channel",
          name: item.snippet.title,
          poster: imageOf(item.snippet.thumbnails),
          description: item.snippet.description || ""
        }));

      } else if (catalogId === "youtube_search") {
        if (search) {
          items = await searchYouTube(youtube, search, false);
        }

      } else if (catalogId === "youtube_music_search") {
        if (search) {
          items = await searchYouTube(youtube, search, true);
        }

      } else if (catalogId === "youtube_trending") {
        const response = await youtube.videos.list({
          part: "snippet,contentDetails",
          chart: "mostPopular",
          regionCode: "US",
          maxResults: 30
        });

        items = (response.data.items || []).map(videoMeta);

      } else {
        return res.status(404).json({
          error: "Catalogue not found.",
          items: [],
          metas: []
        });
      }

      res.json({
        items,
        metas: items
      });
    } catch (error) {
      console.error("Web catalogue error:", error);

      res.status(500).json({
        error: "Unable to load YouTube content.",
        items: [],
        metas: []
      });
    }
  }
);

// LOAD PLAYLIST VIDEOS

app.get(
  "/api/web/playlist/:playlistId",
  requireWebSession,
  async (req, res) => {
    try {
      const youtube = await getYouTubeClient(req.webAccountId);

      const playlistId = req.params.playlistId.replace(
        /^ytplaylist:/,
        ""
      );

      const items = await getPlaylistItems(
        youtube,
        playlistId,
        50
      );

      res.json({
        items,
        metas: items
      });
    } catch (error) {
      console.error("Web playlist error:", error);

      res.status(500).json({
        items: [],
        metas: [],
        error: "Unable to load this playlist."
      });
    }
  }
);

// LOAD CHANNEL VIDEOS

app.get(
  "/api/web/channel/:channelId",
  requireWebSession,
  async (req, res) => {
    try {
      const youtube = await getYouTubeClient(req.webAccountId);

      const channelId = req.params.channelId.replace(
        /^ytchannel:/,
        ""
      );

      const uploadsPlaylist = await getChannelUploadsPlaylist(
        youtube,
        channelId
      );

      if (!uploadsPlaylist) {
        return res.json({
          items: [],
          metas: []
        });
      }

      const items = await getPlaylistItems(
        youtube,
        uploadsPlaylist,
        50
      );

      res.json({
        items,
        metas: items
      });
    } catch (error) {
      console.error("Web channel error:", error);

      res.status(500).json({
        items: [],
        metas: [],
        error: "Unable to load channel videos."
      });
    }
  }
);

// DISCONNECT WEB PLAYER SESSION

app.post("/api/web/disconnect", (req, res) => {
  res.clearCookie("gothika_session", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  });

  res.json({
    success: true
  });
});

// SERVE GOTHIKA WEB PLAYER

app.use(express.static(path.join(process.cwd(), "public")));

app.get("/", (_req, res) => {
  res.sendFile(
    path.join(process.cwd(), "public", "index.html")
  );
});

// START SERVER

app.listen(PORT, () => {
  console.log(`Gothika listening on port ${PORT}`);
});

// END PART 4
