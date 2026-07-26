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

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    phone: user.phone,
    role: user.role,
    status: user.status,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  };
}

async function loadUsers(store) {
  return (await store.get(USER_KEY, { type: "json" })) || [];
}

async function saveUsers(store, users) {
  await store.setJSON(USER_KEY, users);
}

async function currentUser(request, users) {
  const header = request.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;
  const tokenHash = sha256(token);
  return users.find(user => user.status === "active" && (
    user.tokenHash === tokenHash ||
    (Array.isArray(user.sessions) && user.sessions.some(session => session.hash === tokenHash))
  )) || null;
}

function requireText(value) {
  return String(value || "").trim();
}

function issueToken(user) {
  const token = crypto.randomBytes(32).toString("hex");
  user.sessions = Array.isArray(user.sessions) ? user.sessions : [];
  user.sessions.push({ hash: sha256(token), createdAt: new Date().toISOString() });
  user.sessions = user.sessions.slice(-8);
  user.tokenHash = "";
  user.updatedAt = new Date().toISOString();
  return token;
}

export default async (request) => {
  if (request.method === "OPTIONS") return response(204, "");

  const store = getStore("cabinet-team-auth");

  if (request.method === "GET") {
    return response(200, { ok: true, service: "team-auth" });
  }

  if (request.method !== "POST") {
    return response(405, "Unsupported request method.");
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return response(400, "Invalid request body.");
  }

  const users = await loadUsers(store);
  const action = body.action;

  if (action === "register") {
    const name = requireText(body.name);
    const phone = requireText(body.phone);
    const password = requireText(body.password);
    if (!name || !phone || password.length < 6) {
      return response(400, "请填写姓名/店名、手机号和至少 6 位密码。");
    }
    const existing = users.find(user => user.phone === phone);
    if (existing) {
      if (existing.passwordHash === sha256(existing.salt + password) && existing.status === "active") {
        const token = issueToken(existing);
        await saveUsers(store, users);
        return response(200, { user: publicUser(existing), token, alreadyRegisteredLogin: true });
      }
      if (existing.passwordHash === sha256(existing.salt + password)) {
        return response(403, {
          status: existing.status,
          message: existing.status === "pending"
            ? "这个手机号已经提交过注册申请，正在等待超级管理员审核。"
            : "这个手机号已经注册，但账号当前不可用，请联系超级管理员。"
        });
      }
      return response(409, "这个手机号已经注册。请点“登录”；如果登录失败，说明密码不是这一次填写的密码，需要做密码重置。");
    }

    const now = new Date().toISOString();
    const isFirstUser = users.length === 0;
    const salt = crypto.randomBytes(16).toString("hex");
    const user = {
      id: crypto.randomUUID(),
      name,
      phone,
      role: isFirstUser ? "owner" : "designer",
      status: isFirstUser ? "active" : "pending",
      salt,
      passwordHash: sha256(salt + password),
      tokenHash: "",
      sessions: [],
      createdAt: now,
      updatedAt: now
    };

    let token = "";
    if (isFirstUser) {
      token = issueToken(user);
    }

    users.push(user);
    await saveUsers(store, users);
    return response(200, { user: publicUser(user), token, needsApproval: !isFirstUser });
  }

  if (action === "login") {
    const phone = requireText(body.phone);
    const password = requireText(body.password);
    const user = users.find(item => item.phone === phone);
    if (!user || user.passwordHash !== sha256(user.salt + password)) {
      return response(401, "手机号或密码不正确。");
    }
    if (user.status !== "active") {
      const message = user.status === "pending"
        ? "账号还在等待超级管理员审核。"
        : user.status === "disabled"
          ? "账号已被停用，请联系超级管理员。"
          : "账号当前不可用，请联系超级管理员。";
      return response(403, { status: user.status, message });
    }
    const token = issueToken(user);
    await saveUsers(store, users);
    return response(200, { user: publicUser(user), token });
  }

  if (action === "me") {
    const user = await currentUser(request, users);
    if (!user) return response(401, "请重新登录。");
    return response(200, { user: publicUser(user) });
  }

  const actor = await currentUser(request, users);
  if (!actor) return response(401, "请重新登录。");
  if (actor.role !== "owner") return response(403, "只有超级管理员可以管理团队账号。");

  if (action === "listUsers") {
    return response(200, { users: users.map(publicUser) });
  }

  if (action === "updateUser") {
    const target = users.find(user => user.id === body.userId);
    const nextStatus = requireText(body.status);
    if (!target) return response(404, "没有找到这个账号。");
    if (target.id === actor.id && nextStatus !== "active") {
      return response(400, "不能停用或拒绝超级管理员自己的账号。");
    }
    if (!["active", "pending", "rejected", "disabled"].includes(nextStatus)) {
      return response(400, "账号状态不正确。");
    }
    target.status = nextStatus;
    target.updatedAt = new Date().toISOString();
    if (nextStatus !== "active") {
      target.tokenHash = "";
      target.sessions = [];
    }
    await saveUsers(store, users);
    return response(200, { users: users.map(publicUser) });
  }

  if (action === "resetPassword") {
    const target = users.find(user => user.id === body.userId);
    const password = requireText(body.password);
    if (!target) return response(404, "没有找到这个账号。");
    if (password.length < 6) return response(400, "新密码至少需要 6 位。");
    target.salt = crypto.randomBytes(16).toString("hex");
    target.passwordHash = sha256(target.salt + password);
    target.tokenHash = "";
    target.sessions = [];
    target.updatedAt = new Date().toISOString();
    await saveUsers(store, users);
    return response(200, { users: users.map(publicUser) });
  }

  return response(400, "未知操作。");
};
