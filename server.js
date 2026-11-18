
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

const TOKEN_FILE =
  process.env.TOKEN_FILE ||
  path.join(process.cwd(), "data", "youtube-token.enc");

// SUPABASE CONFIGURATION

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const SUPABASE_TABLE =
  process.env.SUPABASE_TABLE || "gothika_tokens";

const TOKEN_ROW_ID = "youtube";

function hasSupabaseConfig() {
  return Boolean(
    SUPABASE_URL &&
    SUPABASE_SERVICE_ROLE_KEY
  );
}

function supabaseEndpoint() {
  if (!hasSupabaseConfig()) {
    throw new Error("Supabase credentials are missing.");
  }

  return (
    SUPABASE_URL.replace(/\/$/, "") +
    "/rest/v1/" +
    encodeURIComponent(SUPABASE_TABLE)
  );
}

const REQUIRED_ENV = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "TOKEN_ENCRYPTION_KEY",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY"
];

const missing = REQUIRED_ENV.filter(
  name => !process.env[name]
);

if (missing.length) {
  console.warn(
    "Missing environment variables:",
    missing.join(", ")
  );
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

function encrypt(text) {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
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

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    raw.subarray(0, 12)
  );

  decipher.setAuthTag(
    raw.subarray(12, 28)
  );

  return Buffer.concat([
    decipher.update(raw.subarray(28)),
    decipher.final()
  ]).toString("utf8");
}

// SUPABASE TOKEN STORAGE

async function saveTokens(tokens) {
  const encryptedToken = encrypt(
    JSON.stringify(tokens)
  );

  if (!hasSupabaseConfig()) {
    throw new Error(
      "Supabase is not configured. Refusing to save tokens locally."
    );
  }

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
      id: TOKEN_ROW_ID,
      encrypted_token: encryptedToken,
      updated_at: new Date().toISOString()
    })
  });

  if (!response.ok) {
    const detail = await response.text();

    throw new Error(
      `Supabase token save failed (${response.status}): ${detail}`
    );
  }

  console.log("Encrypted YouTube tokens saved in Supabase.");
}

async function readLegacyTokenFile() {
  try {
    const encoded = await fs.readFile(
      TOKEN_FILE,
      "utf8"
    );

    return JSON.parse(decrypt(encoded));
  } catch (error) {
    if (error.code === "ENOENT") {
      return null;
    }

    throw error;
  }
}

async function loadTokens() {
  if (!hasSupabaseConfig()) {
    throw new Error(
      "Supabase credentials are not configured."
    );
  }

  const url = new URL(supabaseEndpoint());

  url.searchParams.set("select", "encrypted_token");
  url.searchParams.set("id", `eq.${TOKEN_ROW_ID}`);
  url.searchParams.set("limit", "1");

  const response = await fetch(url, {
    method: "GET",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization:
        `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    }
  });

  if (!response.ok) {
    const detail = await response.text();

    throw new Error(
      `Supabase token read failed (${response.status}): ${detail}`
    );
  }

  const rows = await response.json();

  if (
    rows.length &&
    rows[0].encrypted_token
  ) {
    return JSON.parse(
      decrypt(rows[0].encrypted_token)
    );
  }

  // Migrate an existing local token file if available.

  const oldTokens = await readLegacyTokenFile();

  if (oldTokens) {
    await saveTokens(oldTokens);

    console.log(
      "Existing YouTube sign-in migrated to Supabase."
    );

    return oldTokens;
  }

  return null;
}

// GOOGLE OAUTH

function makeOAuthClient() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error(
      "Google OAuth credentials are not configured."
    );
  }

  return new google.auth.OAuth2(
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI
  );
}

const pendingStates = new Map();

// MANIFEST

const manifest = {
  id: "com.gothika.youtube",
  version: "1.2.0",
  name: "Gothika",
  description:
    "Your personal YouTube playlists, liked videos, subscriptions, music videos and audio tracks.",
  resources: [
    {
      name: "catalog",
      types: ["movie", "other"]
    },
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
      idPrefixes: [
        "ytvideo:",
        "ytaudio:"
      ]
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
      id: "youtube_music_videos",
      name: "Music Videos"
    },
    {
      type: "other",
      id: "youtube_audio_tracks",
      name: "Audio Tracks"
    }
  ],
  behaviorHints: {
    adult: false,
    p2p: false
  }
};

// HOME AND HEALTH

app.get("/", (_req, res) => {
  res.json({
    name: "Gothika",
    status: "online",
    message: "Gothika YouTube addon for Stremio and Nuvio",
    manifest: "/manifest.json",
    catalogues: [
      "My Playlists",
      "Liked Videos",
      "My Subscriptions",
      "Music Videos",
      "Audio Tracks"
    ]
  });
});

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "Gothika"
  });
});

app.get("/manifest.json", (_req, res) => {
  res.json(manifest);
});

// YOUTUBE SIGN-IN

app.get("/auth/youtube", (_req, res) => {
  try {
    const oauth2 = makeOAuthClient();

    const state = crypto
      .randomBytes(24)
      .toString("hex");

    pendingStates.set(state, Date.now());

    for (const [key, createdAt] of pendingStates) {
      if (
        Date.now() - createdAt >
        10 * 60 * 1000
      ) {
        pendingStates.delete(key);
      }
    }

    const url = oauth2.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: true,
      scope: [
        "https://www.googleapis.com/auth/youtube.readonly"
      ],
      state
    });

    res.redirect(url);
  } catch (error) {
    res.status(500).send(
      `Gothika setup error: ${error.message}`
    );
  }
});

app.get(
  "/auth/youtube/callback",
  async (req, res) => {
    try {
      const { code, state, error } = req.query;

      if (error) {
        return res.status(400).send(
          "Google sign-in was cancelled or denied."
        );
      }

      if (
        !code ||
        !state ||
        !pendingStates.has(String(state))
      ) {
        return res.status(400).send(
          "Invalid or expired sign-in request. Please try again."
        );
      }

      pendingStates.delete(String(state));

      const oauth2 = makeOAuthClient();

      const { tokens } = await oauth2.getToken(
        String(code)
      );

      let existing = null;

      try {
        existing = await loadTokens();
      } catch (error) {
        console.warn(
          "Could not load previous token:",
          error.message
        );
      }

      const combinedTokens = {
        ...existing,
        ...tokens,
        refresh_token:
          tokens.refresh_token ||
          existing?.refresh_token
      };

      await saveTokens(combinedTokens);

      res.send(`<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gothika connected</title>
</head>
<body style="font-family:Arial;background:#111;color:#eee;padding:32px">
<h1>Gothika</h1>
<h2>YouTube account connected successfully</h2>
<p>Your encrypted sign-in has been saved securely.</p>
<p>You can close this page and return to Gothika.</p>
</body>
</html>`);
    } catch (error) {
      console.error(
        "YouTube OAuth callback failed:",
        error.message
      );

      res.status(500).send(
        "Gothika could not save your YouTube connection. Check the server logs."
      );
    }
  }
);

// YOUTUBE CLIENT

async function getYouTubeClient() {
  const tokens = await loadTokens();

  if (!tokens) {
    const error = new Error(
      "No YouTube account is connected. Visit /auth/youtube first."
    );

    error.status = 401;

    throw error;
  }

  const oauth2 = makeOAuthClient();

  oauth2.setCredentials(tokens);

  oauth2.on("tokens", async (newTokens) => {
    try {
      const latest = await loadTokens();

      await saveTokens({
        ...latest,
        ...newTokens,
        refresh_token:
          newTokens.refresh_token ||
          latest?.refresh_token ||
          tokens.refresh_token
      });
    } catch (error) {
      console.error(
        "Could not save refreshed YouTube tokens:",
        error.message
      );
    }
  });

  return google.youtube({
    version: "v3",
    auth: oauth2
  });
}

// VIDEO HELPERS

function imageOf(item) {
  const thumbs =
    item.snippet?.thumbnails || {};

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

  if (!id || typeof id !== "string") {
    return null;
  }

  const title =
    item.snippet?.title || "YouTube video";

  const poster = imageOf(item);

  return {
    id: `${audio ? "ytaudio" : "ytvideo"}:${id}`,
    type: audio ? "other" : "movie",
    name: title,
    poster,
    background: poster,
    description:
      item.snippet?.description || "",
    releaseInfo:
      item.snippet?.publishedAt?.slice(0, 4) || ""
  };
}

function isAudioLike(item) {
  const text = (
    `${item.snippet?.title || ""} ` +
    `${item.snippet?.description || ""}`
  ).toLowerCase();

  return /\b(audio|official audio|lyric|lyrics|full album|album track|song|track)\b/.test(text);
}

function isMusicVideoLike(item) {
  const text = (
    `${item.snippet?.title || ""} ` +
    `${item.snippet?.description || ""}`
  ).toLowerCase();

  return /\b(official video|music video|official music video|video clip|mv)\b/.test(text);
}

async function getLikedVideos(youtube) {
  const response = await youtube.videos.list({
    part: ["snippet", "contentDetails"],
    myRating: "like",
    maxResults: 50
  });

  return response.data.items || [];
}

async function getPlaylistItems(
  youtube,
  playlistId
) {
  const response =
    await youtube.playlistItems.list({
      part: [
        "snippet",
        "contentDetails"
      ],
      playlistId,
      maxResults: 50
    });

  return response.data.items || [];
}

// CATALOGUES

app.get(
  "/catalog/:type/:catalogId.json",
  async (req, res) => {
    try {
      const youtube = await getYouTubeClient();

      const { catalogId } = req.params;

      let metas = [];

      if (
        catalogId === "youtube_playlists"
      ) {
        const result =
          await youtube.playlists.list({
            part: [
              "snippet",
              "contentDetails"
            ],
            mine: true,
            maxResults: 50
          });

        metas = (
          result.data.items || []
        ).map(playlist => ({
          id: `ytplaylist:${playlist.id}`,
          type: "other",
          name:
            playlist.snippet?.title ||
            "YouTube playlist",
          poster: imageOf(playlist),
          background: imageOf(playlist),
          description:
            playlist.snippet?.description || "",
          releaseInfo:
            `${playlist.contentDetails?.itemCount || 0} videos`
        }));
      } else if (
        catalogId === "youtube_subscriptions"
      ) {
        const result =
          await youtube.subscriptions.list({
            part: ["snippet"],
            mine: true,
            maxResults: 50
          });

        metas = (
          result.data.items || []
        ).map(subscription => ({
          id:
            `ytchannel:${subscription.snippet?.resourceId?.channelId}`,
          type: "other",
          name:
            subscription.snippet?.title ||
            "YouTube channel",
          poster: imageOf(subscription),
          background: imageOf(subscription),
          description:
            subscription.snippet?.description || ""
        }));
      } else {
        const videos =
          await getLikedVideos(youtube);

        const filtered =
          catalogId === "youtube_music_videos"
            ? videos.filter(isMusicVideoLike)
            : catalogId === "youtube_audio_tracks"
              ? videos.filter(isAudioLike)
              : catalogId === "youtube_liked"
                ? videos
                : [];

        const audio =
          catalogId === "youtube_audio_tracks";

        metas = filtered
          .map(video => videoMeta(video, audio))
          .filter(Boolean);
      }

      res.json({ metas });
    } catch (error) {
      console.error(
        "Catalogue error:",
        error.message
      );

      res.status(error.status || 500).json({
        metas: [],
        error: error.message
      });
    }
  }
);

// METADATA

app.get(
  "/meta/:type/:id.json",
  async (req, res) => {
    try {
      const youtube = await getYouTubeClient();

      const [kind, value] =
        req.params.id.split(":");

      if (kind === "ytplaylist") {
        const items = await getPlaylistItems(
          youtube,
          value
        );

        const videos = items.map(item => {
          const video = videoMeta(item, false);

          return video
            ? {
                id: video.id,
                title: video.name,
                released:
                  item.snippet?.publishedAt,
                thumbnail: video.poster
              }
            : null;
        }).filter(Boolean);

        return res.json({
          meta: {
            id: req.params.id,
            type: "other",
            name: "YouTube playlist",
            videos
          }
        });
      }

      if (kind === "ytchannel") {
        const result =
          await youtube.channels.list({
            part: ["snippet"],
            id: [value]
          });

        const channel =
          result.data.items?.[0];

        if (!channel) {
          return res.status(404).json({
            meta: null
          });
        }

        return res.json({
          meta: {
            id: req.params.id,
            type: "other",
            name:
              channel.snippet?.title ||
              "YouTube channel",
            poster: imageOf(channel),
            description:
              channel.snippet?.description || ""
          }
        });
      }

      if (
        !["ytvideo", "ytaudio"].includes(kind)
      ) {
        return res.status(404).json({
          meta: null
        });
      }

      const result =
        await youtube.videos.list({
          part: [
            "snippet",
            "contentDetails"
          ],
          id: [value]
        });

      const video =
        result.data.items?.[0];

      if (!video) {
        return res.status(404).json({
          meta: null
        });
      }

      res.json({
        meta: videoMeta(
          video,
          kind === "ytaudio"
        )
      });
    } catch (error) {
      res.status(error.status || 500).json({
        meta: null,
        error: error.message
      });
    }
  }
);

// OFFICIAL YOUTUBE PLAYBACK LINKS

app.get(
  "/stream/:type/:id.json",
  async (req, res) => {
    const [kind, videoId] =
      req.params.id.split(":");

    if (
      !["ytvideo", "ytaudio"].includes(kind) ||
      !videoId
    ) {
      return res.json({
        streams: []
      });
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
);

// YOUTUBE ACCOUNT STATUS

app.get(
  "/api/youtube/status",
  async (_req, res) => {
    try {
      const youtube =
        await getYouTubeClient();

      const response =
        await youtube.channels.list({
          part: ["snippet"],
          mine: true
        });

      const channel =
        response.data.items?.[0];

      res.json({
        connected: true,
        channel: channel
          ? {
              title:
                channel.snippet?.title || "",
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
);

// PLAYLIST API

app.get(
  "/api/youtube/playlists",
  async (req, res) => {
    try {
      const youtube =
        await getYouTubeClient();

      const response =
        await youtube.playlists.list({
          part: [
            "snippet",
            "contentDetails"
          ],
          mine: true,
          maxResults: Math.min(
            Number(req.query.maxResults) || 50,
            50
          ),
          pageToken:
            req.query.pageToken || undefined
        });

      res.json({
        items: (
          response.data.items || []
        ).map(item => ({
          id: item.id,
          title:
            item.snippet?.title || "",
          description:
            item.snippet?.description || "",
          thumbnail: imageOf(item),
          videoCount:
            item.contentDetails?.itemCount || 0
        })),
        nextPageToken:
          response.data.nextPageToken || null
      });
    } catch (error) {
      res.status(error.status || 500).json({
        error: error.message
      });
    }
  }
);

// SUBSCRIPTIONS API

app.get(
  "/api/youtube/subscriptions",
  async (req, res) => {
    try {
      const youtube =
        await getYouTubeClient();

      const response =
        await youtube.subscriptions.list({
          part: ["snippet"],
          mine: true,
          maxResults: Math.min(
            Number(req.query.maxResults) || 50,
            50
          ),
          pageToken:
            req.query.pageToken || undefined
        });

      res.json({
        items: (
          response.data.items || []
        ).map(item => ({
          channelId:
            item.snippet?.resourceId?.channelId || "",
          title:
            item.snippet?.title || "",
   
