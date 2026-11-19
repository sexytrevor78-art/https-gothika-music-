
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

const missing = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "TOKEN_ENCRYPTION_KEY",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY"
].filter(name => !process.env[name]);

if (missing.length) {
  console.warn("Missing environment variables:", missing.join(", "));
}

// ACCOUNT HELPERS

function validAccountId(id) {
  return (
    id === LEGACY_ACCOUNT_ID ||
    (typeof id === "string" && /^[a-f0-9]{64}$/i.test(id))
  );
}

function accountIdFromRequest(req) {
  const id = req.params.userId;

  if (!validAccountId(id)) {
    const error = new Error("Invalid Gothika account link.");
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
    res.status(error.status || 400).json({ error: error.message });
  }
}

function createAccountId() {
  return crypto.randomBytes(32).toString("hex");
}

// ENCRYPTION

function getEncryptionKey() {
  if (!ENCRYPTION_KEY || !/^[a-fA-F0-9]{64}$/.test(ENCRYPTION_KEY)) {
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
    throw new Error("Supabase credentials are missing.");
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
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=minimal"
    },
    body: JSON.stringify({
      id: accountId,
      encrypted_token: encrypt(JSON.stringify(tokens)),
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
    const encoded = await fs.readFile(TOKEN_FILE, "utf8");
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
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    }
  });

  if (!response.ok) {
    throw new Error(
      `Supabase read failed (${response.status}): ${await response.text()}`
    );
  }

  const rows = await response.json();

  if (rows.length && rows[0].encrypted_token) {
    return JSON.parse(decrypt(rows[0].encrypted_token));
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
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
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

// GOOGLE SIGN-IN

function makeOAuthClient() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error("Google OAuth credentials are not configured.");
  }

  return new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
  );
}

const pendingStates = new Map();

function cleanPendingStates() {
  const now = Date.now();

  for (const [state, entry] of pendingStates) {
    if (now - entry.createdAt > 600000) {
      pendingStates.delete(state);
    }
  }
}

function publicBaseUrl(req) {
  return (
    process.env.PUBLIC_BASE_URL ||
    `${req.protocol}://${req.get("host")}`
  ).replace(/\/$/, "");
}

function startGoogleSignIn(req, res, accountId) {
  const oauth2 = makeOAuthClient();
  const state = crypto.randomBytes(32).toString("hex");

  cleanPendingStates();

  pendingStates.set(state, {
    accountId,
    createdAt: Date.now()
  });

  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: true,
    scope: ["https://www.googleapis.com/auth/youtube.readonly"],
    state
  });

  res.redirect(url);
}

app.get("/auth/youtube", (req, res) => {
  try {
    startGoogleSignIn(req, res, createAccountId());
  } catch (error) {
    res.status(500).send(`Gothika setup error: ${error.message}`);
  }
});

app.get("/auth/youtube/legacy", (req, res) => {
  try {
    startGoogleSignIn(req, res, LEGACY_ACCOUNT_ID);
  } catch (error) {
    res.status(500).send(`Gothika setup error: ${error.message}`);
  }
});

function successPage(accountId, baseUrl) {
  const manifestUrl =
    `${baseUrl}/u/${accountId}/manifest.json`;

  return `<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gothika connected</title>
</head>
<body style="font-family:Arial;background:#111;color:#eee;padding:28px;max-width:650px;margin:auto">
<h1>Gothika</h1>
<h2>YouTube account connected successfully!</h2>
<p>Your encrypted account connection has been saved.</p>
<p><strong>Your personal Gothika manifest:</strong></p>
<input id="manifest" readonly value="${manifestUrl}" style="box-sizing:border-box;width:100%;padding:12px;background:#222;color:white;border:1px solid #555;border-radius:6px">
<br><br>
<button onclick="navigator.clipboard.writeText(document.getElementById('manifest').value).then(()=>this.innerText='Copied!')" style="padding:12px 18px">Copy manifest URL</button>
<p>Add this personal URL to Stremio.</p>
<p>Keep this URL private. It provides access to your Gothika account.</p>
</body>
</html>`;
}

app.get("/auth/youtube/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send("Google sign-in was cancelled.");
    }

    const stateKey = String(state || "");
    const pending = pendingStates.get(stateKey);

    if (
      !code ||
      !pending ||
      Date.now() - pending.createdAt > 600000
    ) {
      pendingStates.delete(stateKey);
      return res.status(400).send("Invalid or expired sign-in request.");
    }

    pendingStates.delete(stateKey);

    const oauth2 = makeOAuthClient();
    const { tokens } = await oauth2.getToken(String(code));

    const existing = await loadTokens(pending.accountId);

    const combinedTokens = {
      ...existing,
      ...tokens,
      refresh_token: tokens.refresh_token || existing?.refresh_token
    };

    await saveTokens(pending.accountId, combinedTokens);

    res.send(successPage(pending.accountId, publicBaseUrl(req)));
  } catch (error) {
    console.error("OAuth callback failed:", error.message);
    res.status(500).send(
      "Gothika could not save your YouTube connection. Check server logs."
    );
  }
});

// YOUTUBE CLIENT

async function getYouTubeClient(accountId) {
  const tokens = await loadTokens(accountId);

  if (!tokens) {
    const error = new Error(
      "No YouTube account is connected. Visit /auth/youtube first."
    );
    error.status = 401;
    throw error;
  }

  const oauth2 = makeOAuthClient();
  oauth2.setCredentials(tokens);

  oauth2.on("tokens", async newTokens => {
    try {
      const latest = await loadTokens(accountId);

      await saveTokens(accountId, {
        ...latest,
        ...newTokens,
        refresh_token:
          newTokens.refresh_token ||
          latest?.refresh_token ||
          tokens.refresh_token
      });
    } catch (error) {
      console.error("Token refresh save failed:", error.message);
    }
  });

  return google.youtube({
    version: "v3",
    auth: oauth2
  });
}

// VIDEO AND CHANNEL HELPERS

function imageOf(item) {
  const thumbs = item?.snippet?.thumbnails || {};

  return (
    thumbs.maxres?.url ||
    thumbs.high?.url ||
    thumbs.medium?.url ||
    thumbs.default?.url ||
    ""
  );
}

function videoMeta(item, audio = false) {
  const id =
    item.id?.videoId ||
    item.contentDetails?.videoId ||
    item.id;

  if (!id || typeof id !== "string") return null;

  const poster = imageOf(item);

  return {
    id: `${audio ? "ytaudio" : "ytvideo"}:${id}`,
    type: audio ? "other" : "movie",
    name: item.snippet?.title || "YouTube video",
    poster,
    background: poster,
    description: item.snippet?.description || "",
    releaseInfo: item.snippet?.publishedAt?.slice(0, 4) || ""
  };
}

function playlistMeta(item) {
  return {
    id: `ytplaylist:${item.id}`,
    type: "other",
    name: item.snippet?.title || "YouTube playlist",
    poster: imageOf(item),
    background: imageOf(item),
    description: item.snippet?.description || "",
    releaseInfo: `${item.contentDetails?.itemCount || 0} videos`
  };
}

function channelMeta(item) {
  const channelId =
    item.snippet?.resourceId?.channelId || item.id;

  return {
    id: `ytchannel:${channelId}`,
    type: "other",
    name: item.snippet?.title || "YouTube channel",
    poster: imageOf(item),
    background: imageOf(item),
    description: item.snippet?.description || ""
  };
}

async function getPlaylistItems(youtube, playlistId, limit = 200) {
  const items = [];
  let pageToken;

  for (let page = 0; page < Math.ceil(limit / 50); page++) {
    const response = await youtube.playlistItems.list({
      part: ["snippet", "contentDetails"],
      playlistId,
      maxResults: 50,
      pageToken
    });

    items.push(...(response.data.items || []));
    pageToken = response.data.nextPageToken;

    if (!pageToken) break;
  }

  return items.slice(0, limit);
}

async function getChannelUploadsPlaylist(youtube, channelId) {
  const response = await youtube.channels.list({
    part: ["snippet", "contentDetails"],
    id: [channelId]
  });

  const channel = response.data.items?.[0];

  return {
    channel,
    uploadsPlaylistId:
      channel?.contentDetails?.relatedPlaylists?.uploads || null
  };
}

async function getLikedVideos(youtube) {
  const response = await youtube.videos.list({
    part: ["snippet", "contentDetails"],
    myRating: "like",
    maxResults: 50
  });

  return response.data.items || [];
}

async function searchYouTube(youtube, query, musicOnly = false) {
  if (!query || !query.trim()) return [];

  const response = await youtube.search.list({
    part: ["snippet"],
    q: query.trim().slice(0, 150),
    type: ["video"],
    videoCategoryId: musicOnly ? "10" : undefined,
    maxResults: 20,
    safeSearch: "moderate"
  });

  return (response.data.items || [])
    .map(item => videoMeta(item, musicOnly))
    .filter(Boolean);
}

// MANIFEST

function createManifest() {
  const videoSearchExtra = [
    { name: "search", isRequired: true }
  ];

  return {
    id: "com.gothika.youtube",
    version: "3.0.1",
    name: "Gothika",
    description:
      "Browse your YouTube playlists, subscriptions, liked videos and search YouTube.",
    resources: [
      { name: "catalog", types: ["movie", "other"] },
      {
        name: "meta",
        types: ["movie", "other"],
        idPrefixes: [
          "ytvideo:",
          "ytaudio:",
          "ytplaylist:",
          "ytchannel:"
        ]
      },
      {
        name: "stream",
        types: ["movie", "other"],
        idPrefixes: ["ytvideo:", "ytaudio:"]
      }
    ],
    types: ["movie", "other"],
    catalogs: [
      {
        type: "other",
        id: "youtube_playlists",
        name: "My Playlists"
      },
      {
        type: "movie",
        id: "youtube_liked",
        name: "Liked Videos"
      },
      {
        type: "other",
        id: "youtube_subscriptions",
        name: "My Subscriptions"
      },
      {
        type: "movie",
        id: "youtube_search",
        name: "Search YouTube",
        extra: videoSearchExtra
      },
      {
        type: "other",
        id: "youtube_music_search",
        name: "Search Music",
        extra: videoSearchExtra
      },
      {
        type: "movie",
        id: "youtube_trending",
        name: "YouTube Trending"
      }
    ],
    behaviorHints: {
      adult: false,
      p2p: false
    }
  };
}

// HOME, HEALTH AND MANIFEST ROUTES

app.get("/", (_req, res) => {
  res.json({
    name: "Gothika",
    status: "online",
    message: "Gothika YouTube browsing add-on for Stremio",
    connect: "/auth/youtube",
    legacyManifest: "/manifest.json",
    personalManifest: "/u/{your-account-id}/manifest.json",
    features: [
      "YouTube search",
      "Music search",
      "My playlists",
      "Playlist videos",
      "Liked videos",
      "Subscriptions",
      "Channel videos",
      "Trending videos",
      "YouTube playback links"
    ]
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "Gothika" });
});

app.get("/manifest.json", (_req, res) => {
  res.json(createManifest());
});

app.get(
  "/u/:userId/manifest.json",
  requireUserId,
  (_req, res) => {
    res.json(createManifest());
  }
);

// CATALOGUE HANDLER

async function catalogueHandler(req, res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);
    const catalogId = req.params.catalogId;
    const search = String(req.query.search || "").trim();

    let metas = [];

    if (catalogId === "youtube_search") {
      metas = await searchYouTube(youtube, search, false);
    }

    else if (catalogId === "youtube_music_search") {
      metas = await searchYouTube(youtube, search, true);
    }

    else if (catalogId === "youtube_playlists") {
      const result = await youtube.playlists.list({
        part: ["snippet", "contentDetails"],
        mine: true,
        maxResults: 50
      });

      metas = (result.data.items || []).map(playlistMeta);
    }

    else if (catalogId === "youtube_subscriptions") {
      const result = await youtube.subscriptions.list({
        part: ["snippet"],
        mine: true,
        maxResults: 50
      });

      metas = (result.data.items || []).map(channelMeta);
    }

    else if (catalogId === "youtube_liked") {
      const videos = await getLikedVideos(youtube);
      metas = videos.map(item => videoMeta(item)).filter(Boolean);
    }

    else if (catalogId === "youtube_trending") {
      const result = await youtube.videos.list({
        part: ["snippet", "contentDetails"],
        chart: "mostPopular",
        regionCode: "US",
        maxResults: 30
      });

      metas = (result.data.items || [])
        .map(item => videoMeta(item))
        .filter(Boolean);
    }

    res.json({ metas });
  } catch (error) {
    console.error("Catalogue error:", error.message);

    res.status(error.status || 500).json({
      metas: [],
      error: error.message
    });
  }
}

// METADATA HANDLER

async function metadataHandler(req, res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);
    const [kind, value] = req.params.id.split(":");

    if (kind === "ytplaylist") {
      const [playlistResponse, items] = await Promise.all([
        youtube.playlists.list({
          part: ["snippet", "contentDetails"],
          id: [value]
        }),
        getPlaylistItems(youtube, value, 200)
      ]);

      const playlist = playlistResponse.data.items?.[0];

      const videos = items.map(item => {
        const video = videoMeta(item);

        if (!video) return null;

        return {
          id: video.id,
          title: video.name,
          released: item.snippet?.publishedAt || "",
          thumbnail: video.poster
        };
      }).filter(Boolean);

      return res.json({
        meta: {
          id: req.params.id,
          type: "other",
          name: playlist?.snippet?.title || "YouTube playlist",
          poster: imageOf(playlist),
          background: imageOf(playlist),
          description: playlist?.snippet?.description || "",
          videos
        }
      });
    }

    if (kind === "ytchannel") {
      const { channel, uploadsPlaylistId } =
        await getChannelUploadsPlaylist(youtube, value);

      if (!channel) {
        return res.status(404).json({ meta: null });
      }

      let videos = [];

      if (uploadsPlaylistId) {
        const items = await getPlaylistItems(
          youtube,
          uploadsPlaylistId,
          100
        );

        videos = items.map(item => {
          const video = videoMeta(item);
          if (!video) return null;

          return {
            id: video.id,
            title: video.name,
            released: item.snippet?.publishedAt || "",
            thumbnail: video.poster
          };
        }).filter(Boolean);
      }

      return res.json({
        meta: {
          id: req.params.id,
          type: "other",
          name: channel.snippet?.title || "YouTube channel",
          poster: imageOf(channel),
          background: imageOf(channel),
          description: channel.snippet?.description || "",
          videos
        }
      });
    }

    if (!["ytvideo", "ytaudio"].includes(kind)) {
      return res.status(404).json({ meta: null });
    }

    const result = await youtube.videos.list({
      part: ["snippet", "contentDetails"],
      id: [value]
    });

    const video = result.data.items?.[0];

    if (!video) {
      return res.status(404).json({ meta: null });
    }

    return res.json({
      meta: videoMeta(video, kind === "ytaudio")
    });
  } catch (error) {
    console.error("Metadata error:", error.message);

    res.status(error.status || 500).json({
      meta: null,
      error: error.message
    });
  }
}

// STREAM HANDLER - DIRECT YOUTUBE LINKS

function streamHandler(req, res) {
  const [kind, videoId] = req.params.id.split(":");

  if (!["ytvideo", "ytaudio"].includes(kind) || !videoId) {
    return res.json({ streams: [] });
  }

  const watchUrl =
    `https://www.youtube.com/watch?v=${encodeURIComponent(videoId)}`;

  res.json({
    streams: [
      {
        name: "Gothika • YouTube",
        title: "▶ Open on YouTube",
        externalUrl: watchUrl
      }
    ]
  });
}

// LEGACY ROUTES

app.get("/catalog/:type/:catalogId.json", async (req, res) => {
  await catalogueHandler(req, res, LEGACY_ACCOUNT_ID);
});

app.get("/meta/:type/:id.json", async (req, res) => {
  await metadataHandler(req, res, LEGACY_ACCOUNT_ID);
});

app.get("/stream/:type/:id.json", streamHandler);

// PERSONAL ACCOUNT ROUTES

app.get(
  "/u/:userId/catalog/:type/:catalogId.json",
  requireUserId,
  async (req, res) => {
    await catalogueHandler(req, res, accountIdFromRequest(req));
  }
);

app.get(
  "/u/:userId/meta/:type/:id.json",
  requireUserId,
  async (req, res) => {
    await metadataHandler(req, res, accountIdFromRequest(req));
  }
);

app.get(
  "/u/:userId/stream/:type/:id.json",
  requireUserId,
  streamHandler
);

// ACCOUNT STATUS

async function accountStatusHandler(res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);

    const response = await youtube.channels.list({
      part: ["snippet"],
      mine: true
    });

    const channel = response.data.items?.[0];

    res.json({
      connected: true,
      channel: channel
        ? {
            title: channel.snippet?.title || "",
            thumbnail: imageOf(channel)
          }
        : null,
      tokenStorage: "Supabase"
    });
  } catch (error) {
    res.status(error.status || 500).json({
      connected: false,
      error: error.message
    });
  }
}

app.get("/api/youtube/status", async (_req, res) => {
  await accountStatusHandler(res, LEGACY_ACCOUNT_ID);
});

app.get(
  "/u/:userId/api/youtube/status",
  requireUserId,
  async (req, res) => {
    await accountStatusHandler(res, accountIdFromRequest(req));
  }
);

// PLAYLIST API

async function playlistsHandler(req, res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);

    const response = await youtube.playlists.list({
      part: ["snippet", "contentDetails"],
      mine: true,
      maxResults: 50,
      pageToken: req.query.pageToken || undefined
    });

    res.json({
      items: (response.data.items || []).map(item => ({
        id: item.id,
        title: item.snippet?.title || "",
        description: item.snippet?.description || "",
        thumbnail: imageOf(item),
        videoCount: item.contentDetails?.itemCount || 0
      })),
      nextPageToken: response.data.nextPageToken || null
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
}

app.get("/api/youtube/playlists", async (req, res) => {
  await playlistsHandler(req, res, LEGACY_ACCOUNT_ID);
});

app.get(
  "/u/:userId/api/youtube/playlists",
  requireUserId,
  async (req, res) => {
    await playlistsHandler(req, res, accountIdFromRequest(req));
  }
);

// SUBSCRIPTIONS API

async function subscriptionsHandler(req, res, accountId) {
  try {
    const youtube = await getYouTubeClient(accountId);

    const response = await youtube.subscriptions.list({
      part: ["snippet"],
      mine: true,
      maxResults: 50,
      pageToken: req.query.pageToken || undefined
    });

    res.json({
      items: (response.data.items || []).map(item => ({
        channelId: item.snippet?.resourceId?.channelId || "",
        title: item.snippet?.title || "",
        description: item.snippet?.description || "",
        thumbnail: imageOf(item)
      })),
      nextPageToken: response.data.nextPageToken || null
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message });
  }
}

app.get("/api/youtube/subscriptions", async (req, res) => {
  await subscriptionsHandler(req, res, LEGACY_ACCOUNT_ID);
});

app.get(
  "/u/:userId/api/youtube/subscriptions",
  requireUserId,
  async (req, res) => {
    await subscriptionsHandler(req, res, accountIdFromRequest(req));
  }
);

// DISCONNECT

async function disconnectHandler(res, accountId) {
  try {
    await deleteTokens(accountId);

    res.json({
      success: true,
      connected: false
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}

app.post("/api/youtube/disconnect", async (_req, res) => {
  await disconnectHandler(res, LEGACY_ACCOUNT_ID);
});

app.post(
  "/u/:userId/api/youtube/disconnect",
  requireUserId,
  async (req, res) => {
    await disconnectHandler(res, accountIdFromRequest(req));
  }
);

// START SERVER

app.listen(PORT, () => {
  console.log(`Gothika listening on port ${PORT}`);
});
