const crypto = require("crypto");
let getStore;

try {
  ({ getStore } = require("@netlify/blobs"));
} catch (error) {
  getStore = null;
}

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type,x-sync-password",
      "access-control-allow-methods": "GET,POST,OPTIONS"
    },
    body: JSON.stringify(body)
  };
}

function text(statusCode, body) {
  return {
    statusCode,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type,x-sync-password",
      "access-control-allow-methods": "GET,POST,OPTIONS"
    },
    body
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return text(204, "");

  const password = event.headers["x-sync-password"] || event.headers["X-Sync-Password"] || "";
  if (!password || password.length < 6) {
    return text(400, "Sync password must be at least 6 characters.");
  }

  if (!getStore) {
    return text(500, "Netlify Blobs failed to load. Please deploy the full cloud-deploy folder with package.json.");
  }

  const key = crypto.createHash("sha256").update(password).digest("hex");
  let store;
  try {
    store = getStore("cabinet-workbench");
  } catch (error) {
    return text(500, "Netlify Blobs init failed: " + error.message);
  }

  if (event.httpMethod === "GET") {
    try {
      const saved = await store.get(key, { type: "json" });
      if (!saved) return text(404, "No cloud data exists for this sync password yet.");
      return json(200, { state: saved });
    } catch (error) {
      return text(500, "Cloud read failed: " + error.message);
    }
  }

  if (event.httpMethod === "POST") {
    let payload;
    try {
      payload = JSON.parse(event.body || "{}");
    } catch {
      return text(400, "Save failed: invalid data format.");
    }
    if (!payload.state || typeof payload.state !== "object") {
      return text(400, "Save failed: no workbench data received.");
    }
    try {
      await store.setJSON(key, payload.state);
      return json(200, { ok: true });
    } catch (error) {
      return text(500, "Cloud write failed: " + error.message);
    }
  }

  return text(405, "Unsupported request method.");
};
