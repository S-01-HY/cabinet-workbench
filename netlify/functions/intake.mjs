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
  return users.find(user => user.status === "active" && (
    user.tokenHash === tokenHash ||
    (Array.isArray(user.sessions) && user.sessions.some(session => session.hash === tokenHash))
  )) || null;
}

function dataKey(userId) {
  return "state:" + userId;
}

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function newPlanFromSubmission(payload) {
  const needs = payload.needs && typeof payload.needs === "object" ? payload.needs : {
    "玄关": { status: "可选", note: payload.entryNeed || "", cabinets: [], functions: [], doorPrefs: [] },
    "客餐厅": { status: "可选", note: payload.livingNeed || "", cabinets: [], functions: [], doorPrefs: [] },
    "主卧": { status: "可选", note: payload.bedroomNeed || "", cabinets: [], functions: [], doorPrefs: [] },
    "厨房": { status: "可选", note: payload.kitchenNeed || "", cabinets: [], functions: [], doorPrefs: [] }
  };
  return { id: uid(), name: "客户填写需求", cabinets: [], addons: [], needs, revisions: [], checks: [] };
}

function newCustomerFromSubmission(payload) {
  const room = String(payload.room || "客户填写").trim() || "客户填写";
  const style = String(payload.style || "现代简约").trim();
  const livingColor = String(payload.livingColor || "").trim();
  const bedroomColor = String(payload.bedroomColor || "").trim();
  const colorPrefsLiving = Array.isArray(payload.colorPrefsLiving) ? payload.colorPrefsLiving : [];
  const colorPrefsBedroom = Array.isArray(payload.colorPrefsBedroom) ? payload.colorPrefsBedroom : [];
  const notes = [
    String(payload.notes || "").trim(),
    [...colorPrefsLiving, livingColor].filter(Boolean).length ? "客餐厅配色：" + [...colorPrefsLiving, livingColor].filter(Boolean).join("、") : "",
    [...colorPrefsBedroom, bedroomColor].filter(Boolean).length ? "卧室配色：" + [...colorPrefsBedroom, bedroomColor].filter(Boolean).join("、") : ""
  ].filter(Boolean).join("\n");
  return {
    id: uid(),
    room,
    quoteDate: today(),
    reminder: today(),
    status: "已量尺",
    layout: "",
    budget: "暂未明确",
    notes,
    style,
    styleNote: "客户填写链接提交",
    colorPrefsLiving,
    colorNoteLiving: livingColor,
    colorPrefsBedroom,
    colorNoteBedroom: bedroomColor,
    referencePhotos: Array.isArray(payload.referencePhotos) ? payload.referencePhotos.slice(0, 8) : [],
    photos: [],
    plans: [newPlanFromSubmission(payload)]
  };
}

export default async (request) => {
  if (request.method === "OPTIONS") return response(204, "");

  const intakeStore = getStore("cabinet-intake-links");
  const dataStore = getStore("cabinet-workbench-team-data");

  if (request.method === "GET") {
    const url = new URL(request.url);
    const token = url.searchParams.get("token") || "";
    if (!token) return response(400, "缺少客户填写链接编号。");
    const link = await intakeStore.get("link:" + token, { type: "json" });
    if (!link || link.status !== "active") return response(404, "客户填写链接不存在或已停用。");
    return response(200, { room: link.room || "", designerName: link.designerName || "" });
  }

  if (request.method !== "POST") return response(405, "Unsupported request method.");

  let body;
  try {
    body = await request.json();
  } catch {
    return response(400, "数据格式不正确。");
  }

  if (body.action === "create") {
    const actor = await currentUser(request);
    if (!actor) return response(401, "请先登录再生成客户填写链接。");
    const token = crypto.randomBytes(18).toString("hex");
    const link = {
      token,
      ownerId: actor.id,
      designerName: actor.name,
      room: String(body.room || "").trim(),
      status: "active",
      createdAt: new Date().toISOString()
    };
    await intakeStore.setJSON("link:" + token, link);
    return response(200, { token, room: link.room });
  }

  if (body.action === "submit") {
    const token = String(body.token || "").trim();
    if (!token) return response(400, "缺少客户填写链接编号。");
    const link = await intakeStore.get("link:" + token, { type: "json" });
    if (!link || link.status !== "active") return response(404, "客户填写链接不存在或已停用。");
    const state = (await dataStore.get(dataKey(link.ownerId), { type: "json" })) || {
      activeCustomerId: null,
      customers: [],
      priceRules: [],
      addonRules: []
    };
    state.customers ||= [];
    const customer = newCustomerFromSubmission({ ...body, room: body.room || link.room });
    state.customers.unshift(customer);
    state.activeCustomerId = customer.id;
    await dataStore.setJSON(dataKey(link.ownerId), state);
    return response(200, { ok: true });
  }

  return response(400, "未知操作。");
};
