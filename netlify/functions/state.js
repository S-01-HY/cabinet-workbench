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
    return text(400, "同步密码至少需要 6 位。");
  }

  if (!getStore) {
    return text(500, "Netlify Blobs 没有加载成功。请确认上传的是包含 package.json 的完整 cloud-deploy 文件夹或 zip。");
  }

  const key = crypto.createHash("sha256").update(password).digest("hex");
  let store;
  try {
    store = getStore("cabinet-workbench");
  } catch (error) {
    return text(500, "Netlify Blobs 初始化失败：" + error.message);
  }

  if (event.httpMethod === "GET") {
    try {
      const saved = await store.get(key, { type: "json" });
      if (!saved) return text(404, "这个同步密码还没有云端数据。");
      return json(200, { state: saved });
    } catch (error) {
      return text(500, "读取云端失败：" + error.message);
    }
  }

  if (event.httpMethod === "POST") {
    let payload;
    try {
      payload = JSON.parse(event.body || "{}");
    } catch {
      return text(400, "保存失败：数据格式不正确。");
    }
    if (!payload.state || typeof payload.state !== "object") {
      return text(400, "保存失败：没有收到工作台数据。");
    }
    try {
      await store.setJSON(key, payload.state);
      return json(200, { ok: true });
    } catch (error) {
      return text(500, "写入云端失败：" + error.message);
    }
  }

  return text(405, "不支持这个请求。");
};
