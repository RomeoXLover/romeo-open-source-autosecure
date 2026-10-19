/**
 * Cloudflare Worker — Email Routing OTP Forwarder
 * Receives email via Cloudflare Email Routing → forwards body to romeo-bot
 *
 * Deploy:
 *   - Set up Cloudflare Email Routing to forward to this worker
 *   - Route: yourdomain.com/* → this worker
 *   - Set secrets: WORKER_SECRET (matches extracted/token.json → cloudflare.secret)
 *
 * Usage:
 *   Email arrives via Email Routing → worker extracts subject/body →
 *   POSTs to http://127.0.0.1:8765/mail with X-CF-Secret header
 */

const TARGET_URL = "http://127.0.0.1:8765/mail";
const SHARED_SECRET = WORKER_SECRET || "CHANGE_ME";

addEventListener("email", (event) => {
  event.waitUntil(handleEmail(event.email));
});

async function handleEmail(email) {
  const subject = email.subject || "(no subject)";
  const rawBody = await email.raw();
  const bodyText = rawToString(rawBody);

  // Build a simplified body — extract text from RFC822
  const body = extractTextBody(rawBody);

  await fetch(TARGET_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CF-Secret": SHARED_SECRET,
    },
    body: JSON.stringify({
      subject: subject,
      body: body,
      from: email.from?.email || "",
    }),
  });
}

function extractTextBody(raw) {
  // crude multipart extraction — real impl uses proper MIME parsing
  const lines = raw.split("\r\n");
  let inBody = false;
  let body = "";

  for (const line of lines) {
    if (inBody) {
      body += line + "\n";
    }
    if (line.trim() === "") {
      inBody = true;
    }
  }

  return body.substring(0, 2048);
}

function rawToString(raw) {
  if (typeof raw === "string") return raw;
  return new TextDecoder().decode(raw);
}

// Health check endpoint
addEventListener("fetch", (event) => {
  event.respondWith(new Response("Worker running", { status: 200 }));
});
