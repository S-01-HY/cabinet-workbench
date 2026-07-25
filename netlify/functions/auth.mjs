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
  return users.find(user => user.tokenHash === tokenHash && user.status === "active") || null;
}

function requireText(value) {
  return String(value || "").trim();
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
      return response(400, "Name, phone, and a 6+ character password are required.");
    }
    if (users.some(user => user.phone === phone)) {
      return response(409, "This phone number has already been registered.");
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
      createdAt: now,
      updatedAt: now
    };

    let token = "";
    if (isFirstUser) {
      token = crypto.randomBytes(32).toString("hex");
      user.tokenHash = sha256(token);
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
      return response(401, "Phone number or password is incorrect.");
    }
    if (user.status !== "active") {
      return response(403, { status: user.status, message: "This account is not active." });
    }
    const token = crypto.randomBytes(32).toString("hex");
    user.tokenHash = sha256(token);
    user.updatedAt = new Date().toISOString();
    await saveUsers(store, users);
    return response(200, { user: publicUser(user), token });
  }

  if (action === "me") {
    const user = await currentUser(request, users);
    if (!user) return response(401, "Please log in again.");
    return response(200, { user: publicUser(user) });
  }

  const actor = await currentUser(request, users);
  if (!actor) return response(401, "Please log in again.");
  if (actor.role !== "owner") return response(403, "Only the owner can manage team accounts.");

  if (action === "listUsers") {
    return response(200, { users: users.map(publicUser) });
  }

  if (action === "updateUser") {
    const target = users.find(user => user.id === body.userId);
    const nextStatus = requireText(body.status);
    if (!target) return response(404, "User not found.");
    if (target.id === actor.id && nextStatus !== "active") {
      return response(400, "The owner account cannot be disabled or rejected.");
    }
    if (!["active", "pending", "rejected", "disabled"].includes(nextStatus)) {
      return response(400, "Invalid status.");
    }
    target.status = nextStatus;
    target.updatedAt = new Date().toISOString();
    if (nextStatus !== "active") target.tokenHash = "";
    await saveUsers(store, users);
    return response(200, { users: users.map(publicUser) });
  }

  return response(400, "Unknown action.");
};
