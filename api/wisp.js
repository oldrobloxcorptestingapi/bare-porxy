/**
 * Ultraviolet — Wisp WebSocket Server
 * Vercel Serverless Function (Node.js 18+)
 *
 * Implements the Wisp v1 protocol:
 * https://github.com/MercuryWorkshop/wisp-protocol/blob/main/protocol.md
 *
 * Wisp multiplexes many TCP streams over a single WebSocket using binary frames:
 *
 *  CONNECT  [0x01][stream_id u32le][stream_type u8][port u16le][hostname...]
 *  DATA     [0x02][stream_id u32le][payload...]
 *  CONTINUE [0x04][stream_id u32le][buffer_remaining u32le]
 *  CLOSE    [0x03][stream_id u32le][reason u8]
 */

import { WebSocketServer } from "ws";
import net from "net";

// ── Config ─────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*")
  .split(",")
  .map((s) => s.trim());

// Wisp packet types
const PKT = { CONNECT: 0x01, DATA: 0x02, CLOSE: 0x03, CONTINUE: 0x04 };

// Close reasons
const CLOSE = {
  OK: 0x01,
  NETWORK: 0x02,
  UNREACHABLE: 0x03,
  TIMEOUT: 0x41,
  BLOCKED: 0x48,
};

// Flow control: how many bytes we advertise per stream
const BUFFER_SIZE = 1 << 16; // 64 KiB

// ── Vercel function config ─────────────────────────────────────────────────────
export const config = {
  api: {
    bodyParser: false,      // Don't buffer the body — we take over the socket
    externalResolver: true, // Tell Vercel we handle the response ourselves
  },
};

// ── Singleton WSS (reused across warm invocations) ───────────────────────────
const wss = new WebSocketServer({ noServer: true });

// ── Origin check ──────────────────────────────────────────────────────────────
function isAllowed(origin) {
  if (ALLOWED_ORIGINS.includes("*")) return true;
  if (!origin) return true; // no origin header = non-browser (CLI, tests)
  return ALLOWED_ORIGINS.includes(origin);
}

// ── Frame builders ────────────────────────────────────────────────────────────
function makeClose(streamId, reason) {
  const buf = Buffer.allocUnsafe(6);
  buf[0] = PKT.CLOSE;
  buf.writeUInt32LE(streamId, 1);
  buf[5] = reason;
  return buf;
}

function makeContinue(streamId, remaining) {
  const buf = Buffer.allocUnsafe(9);
  buf[0] = PKT.CONTINUE;
  buf.writeUInt32LE(streamId, 1);
  buf.writeUInt32LE(remaining, 5);
  return buf;
}

function makeData(streamId, payload) {
  const hdr = Buffer.allocUnsafe(5);
  hdr[0] = PKT.DATA;
  hdr.writeUInt32LE(streamId, 1);
  return Buffer.concat([hdr, payload]);
}

// ── Handle one WebSocket client ───────────────────────────────────────────────
function handleClient(ws) {
  /** @type {Map<number, net.Socket>} */
  const streams = new Map();

  function closeStream(streamId, reason, sendFrame = true) {
    const sock = streams.get(streamId);
    if (!sock) return;
    streams.delete(streamId);
    sock.destroy();
    if (sendFrame && ws.readyState === ws.OPEN) {
      ws.send(makeClose(streamId, reason));
    }
  }

  // ── Incoming WebSocket frames ───────────────────────────────────────────────
  ws.on("message", (raw) => {
    if (!Buffer.isBuffer(raw)) raw = Buffer.from(raw);
    if (raw.length < 5) return; // too short to be a valid frame

    const type = raw[0];
    const streamId = raw.readUInt32LE(1);

    // ── CONNECT ──────────────────────────────────────────────────────────────
    if (type === PKT.CONNECT) {
      if (raw.length < 8) return;
      const streamType = raw[5];      // 0x01 = TCP, 0x03 = UDP (we support TCP)
      const port = raw.readUInt16LE(6);
      const hostname = raw.slice(8).toString("ascii");

      if (streamType !== 0x01) {
        // UDP not supported — close immediately
        ws.send(makeClose(streamId, CLOSE.BLOCKED));
        return;
      }

      const sock = net.createConnection({ host: hostname, port }, () => {
        // Advertise initial buffer to the client
        if (ws.readyState === ws.OPEN) {
          ws.send(makeContinue(streamId, BUFFER_SIZE));
        }
      });

      sock.on("data", (chunk) => {
        if (ws.readyState === ws.OPEN) {
          ws.send(makeData(streamId, chunk));
        }
      });

      sock.on("close", () => closeStream(streamId, CLOSE.OK, true));
      sock.on("error", (err) => {
        const reason =
          err.code === "ECONNREFUSED" || err.code === "ENOTFOUND"
            ? CLOSE.UNREACHABLE
            : CLOSE.NETWORK;
        closeStream(streamId, reason, true);
      });
      sock.setTimeout(30_000, () => closeStream(streamId, CLOSE.TIMEOUT, true));

      streams.set(streamId, sock);
      return;
    }

    // ── DATA ─────────────────────────────────────────────────────────────────
    if (type === PKT.DATA) {
      const sock = streams.get(streamId);
      if (!sock || sock.destroyed) return;
      const payload = raw.slice(5);
      sock.write(payload, () => {
        // Re-advertise buffer after draining
        if (ws.readyState === ws.OPEN) {
          ws.send(makeContinue(streamId, BUFFER_SIZE));
        }
      });
      return;
    }

    // ── CLOSE (client-initiated) ──────────────────────────────────────────────
    if (type === PKT.CLOSE) {
      closeStream(streamId, CLOSE.OK, false);
    }
  });

  ws.on("close", () => {
    for (const [id] of streams) closeStream(id, CLOSE.OK, false);
  });

  ws.on("error", () => {
    for (const [id] of streams) closeStream(id, CLOSE.OK, false);
  });
}

// ── Vercel handler ─────────────────────────────────────────────────────────────
export default function handler(req, res) {
  // Non-WebSocket requests (health check, OPTIONS)
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version");
    res.statusCode = 204;
    res.end();
    return;
  }

  if (req.headers.upgrade?.toLowerCase() !== "websocket") {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ status: "ok", wisp: "/wisp/" }));
    return;
  }

  // Origin check
  if (!isAllowed(req.headers.origin)) {
    res.statusCode = 403;
    res.end("Forbidden");
    return;
  }

  // Hand the raw TCP socket to the WS server for the handshake
  wss.handleUpgrade(req, req.socket, Buffer.alloc(0), (ws) => {
    wss.emit("connection", ws, req);
    handleClient(ws);
  });
}

// Attach client handler to wss connection event (for completeness)
wss.on("connection", () => {}); // handleClient called directly above
