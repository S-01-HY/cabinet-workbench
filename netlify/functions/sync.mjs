import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

function response(status, body, contentType = "text/plain; charset=utf-8") {
  const isText = typeof body === "string";
  return new Response(isText ? body : JSON.stringify(body), {
    status,
    headers: {
      "content-type": isText ? contentType : "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type,x-sync-password",
      "access-control-allow-methods": "GET,POST,OPTIONS"
    }
  });
}

export default async (request) => {
  if (request.method === "OPTIONS") return response(204, "");

  const password = request.headers.get("x-sync-password") || "";
  if (password.length < 6) {
    return response(400, "Sync password must be at least 6 characters.");
  }

  const key = crypto.createHash("sha256").update(password).digest("hex");
  const store = getStore("cabinet-workbench");

  if (request.method === "GET") {
    const saved = await store.get(key, { type: "json" });
    if (!saved) return response(404, "No cloud data exists for this sync password yet.");
    return response(200, { state: saved });
  }

  if (request.method === "POST") {
    let payload;
    try {
      payload = await request.json();
    } catch {
      return response(400, "Save failed: invalid data format.");
    }

    if (!payload.state || typeof payload.state !== "object") {
      return response(400, "Save failed: no workbench data received.");
    }

    await store.setJSON(key, payload.state);
    return response(200, { ok: true });
  }

  return response(405, "Unsupported request method.");
};
