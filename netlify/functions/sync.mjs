import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

const USER_KEY = "users";

function response(status, body) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: {
      "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type,authorization",
      "access-control-allow-methods": "GET,POST,OPTIONS"
    }
  });
}

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

async function currentUser(request) {
  const header = request.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;
  const users = (await getStore("cabinet-team-auth").get(USER_KEY, { type: "json" })) || [];
  const tokenHash = sha256(token);
  return users.find(user => user.tokenHash === tokenHash && user.status === "active") || null;
}

function dataKey(userId) {
  return "state:" + userId;
}

function targetOwnerId(request, actor, body = {}) {
  const url = new URL(request.url);
  const requested = body.ownerId || url.searchParams.get("ownerId") || actor.id;
  if (actor.role === "owner") return requested;
  return actor.id;
}

export default async (request) => {
  if (request.method === "OPTIONS") return response(204, "");

  const actor = await currentUser(request);
  if (!actor) return response(401, "Please log in before syncing data.");

  const store = getStore("cabinet-workbench-team-data");

  if (request.method === "GET") {
    const ownerId = targetOwnerId(request, actor);
    const saved = await store.get(dataKey(ownerId), { type: "json" });
    if (!saved) return response(404, "No cloud data exists for this account yet.");
    return response(200, { state: saved, ownerId });
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
    const ownerId = targetOwnerId(request, actor, payload);
    await store.setJSON(dataKey(ownerId), payload.state);
    return response(200, { ok: true, ownerId });
  }

  return response(405, "Unsupported request method.");
};
