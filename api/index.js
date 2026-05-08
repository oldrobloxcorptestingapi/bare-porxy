/**
 * GET / → health check / status page
 * Vercel will serve this at the root of the backend domain.
 */
export default function handler(req, res) {
  res.setHeader("Content-Type", "application/json");
  res.end(
    JSON.stringify({
      status: "ok",
      service: "Ultraviolet Wisp Backend",
      wisp_endpoint: "/wisp/",
      note: "Connect via wss:// — this endpoint only responds to WebSocket upgrades.",
    })
  );
}
