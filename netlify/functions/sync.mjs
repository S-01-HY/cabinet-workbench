import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

const USER_KEY = "users";
const TEAM_PRICES_KEY = "team-price-library";

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
  const user = users.find(user => user.tokenHash === tokenHash && user.status === "active") || null;
  return user ? { user, users } : null;
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

  const session = await currentUser(request);
  if (!session) return response(401, "请先登录再同步数据。");
  const actor = session.user;

  const store = getStore("cabinet-workbench-team-data");

  if (request.method === "GET") {
    const url = new URL(request.url);
    const resource = url.searchParams.get("resource") || "state";
    if (resource === "teamPrices") {
      const saved = await store.get(TEAM_PRICES_KEY, { type: "json" });
      return response(200, saved || { priceRules: [], addonRules: [] });
    }
    if (resource === "allStates") {
      if (actor.role !== "owner") return response(403, "只有超级管理员可以导出全部设计师数据。");
      const activeUsers = session.users.filter(user => user.status === "active");
      const states = [];
      for (const user of activeUsers) {
        const saved = await store.get(dataKey(user.id), { type: "json" });
        states.push({ owner: { id: user.id, name: user.name, phone: user.phone, role: user.role }, state: saved || null });
      }
      return response(200, { states });
    }
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
    if (payload.resource === "teamPrices") {
      if (actor.role !== "owner") return response(403, "只有超级管理员可以维护团队公共价格库。");
      const priceRules = Array.isArray(payload.priceRules) ? payload.priceRules : [];
      const addonRules = Array.isArray(payload.addonRules) ? payload.addonRules : [];
      await store.setJSON(TEAM_PRICES_KEY, { priceRules, addonRules, updatedAt: new Date().toISOString() });
      return response(200, { ok: true });
    }
    if (!payload.state || typeof payload.state !== "object") {
      return response(400, "没有收到需要保存的工作台数据。");
    }
    const ownerId = targetOwnerId(request, actor, payload);
    await store.setJSON(dataKey(ownerId), payload.state);
    return response(200, { ok: true, ownerId });
  }

  return response(405, "Unsupported request method.");
};
