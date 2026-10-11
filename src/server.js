const http = require('node:http');
const https = require('node:https');

const PORT = parseInt(process.env.PORT, 10) || 61010;
const HOST = process.env.HOST || '0.0.0.0';

// ── 请求头清洗：去掉不应透传给目标的 header ──────────────────────
const REQUEST_HEADER_BLOCKLIST = new Set([
  'host',                    // 指向代理，非目标
  'origin',                  // 暴露代理
  'referer',                 // 暴露代理
  'cookie',                  // 安全：泄漏用户凭证
  'authorization',           // 安全：泄漏用户凭证
  'proxy-authorization',     // 安全：代理认证信息
]);

// ── 响应头清洗：去掉不应返回给浏览器的 header ────────────────────
const RESPONSE_HEADER_BLOCKLIST = new Set([
  'set-cookie',                      // 浏览器拒绝第三方 cookie
  'content-security-policy',         // 可能阻断响应
  'content-security-policy-report-only',
  'x-frame-options',                 // 可能阻断响应
  'strict-transport-security',       // 不应由代理注入
  'www-authenticate',                // 安全：不暴露目标认证方式
  'proxy-authenticate',
]);

function cleanRequestHeaders(headers) {
  const cleaned = {};
  for (const [key, val] of Object.entries(headers)) {
    if (!REQUEST_HEADER_BLOCKLIST.has(key.toLowerCase())) {
      cleaned[key] = val;
    }
  }
  return cleaned;
}

function cleanResponseHeaders(headers) {
  const cleaned = {};
  for (const [key, val] of Object.entries(headers)) {
    if (!RESPONSE_HEADER_BLOCKLIST.has(key.toLowerCase())) {
      cleaned[key] = val;
    }
  }
  // CORS 代理的核心价值：允许任意来源访问
  cleaned['access-control-allow-origin'] = '*';
  // 允许浏览器读取的响应头白名单
  cleaned['access-control-expose-headers'] = '*';
  return cleaned;
}

// ── 主服务 ─────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  const fullUrl = `http://${req.headers.host || 'localhost'}${req.url}`;
  const { pathname, search } = new URL(fullUrl);

  if (pathname !== '/') {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('404 - 仅 /?url=<url> 可用喵～♪');
    return;
  }

  // 从原始 query string 中手动提取 url= 之后的所有内容
  // 不能用 URLSearchParams.get()——目标 URL 自身含 & 时会被截断
  const targetUrl = search.startsWith('?url=') ? decodeURIComponent(search.slice(5)) : null;
  if (!targetUrl) {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('缺少 url 参数喵～ 用法: /?url=<url>');
    return;
  }

  let target;
  try {
    target = new URL(targetUrl);
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('url 格式不合法喵～');
    return;
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('仅支持 http / https 协议喵～');
    return;
  }

  // 处理 OPTIONS 预检请求
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS',
      'access-control-allow-headers': '*',
      'access-control-max-age': '86400',
    });
    res.end();
    return;
  }

  const transport = target.protocol === 'https:' ? https : http;
  const cleanedHeaders = cleanRequestHeaders(req.headers);

  const proxyReq = transport.request(
    {
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: target.pathname + target.search,
      method: req.method,
      headers: {
        ...cleanedHeaders,
        host: target.host, // 修正 Host 头指向真实目标
      },
    },
    (proxyRes) => {
      const cleanedResHeaders = cleanResponseHeaders(proxyRes.headers);
      res.writeHead(proxyRes.statusCode, cleanedResHeaders);
      proxyRes.pipe(res);
    },
  );

  proxyReq.on('error', (err) => {
    console.error(`[proxy error] ${targetUrl}: ${err.message}`);
    // 如果已经发送了响应头则直接销毁 socket
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(502, {
      'content-type': 'text/plain; charset=utf-8',
      'access-control-allow-origin': '*',
    });
    res.end(`代理请求失败喵～ ${err.message}`);
  });

  // 限制请求体大小（防止内存攻击），默认 10MB
  const MAX_BODY = parseInt(process.env.MAX_BODY, 10) || 10 * 1024 * 1024;
  let bodySize = 0;
  req.on('data', (chunk) => {
    bodySize += chunk.length;
    if (bodySize > MAX_BODY) {
      proxyReq.destroy();
      req.destroy();
      if (!res.headersSent) {
        res.writeHead(413, {
          'content-type': 'text/plain; charset=utf-8',
          'access-control-allow-origin': '*',
        });
        res.end('请求体过大喵～');
      }
      return;
    }
    if (!proxyReq.destroyed) proxyReq.write(chunk);
  });
  req.on('end', () => {
    if (!proxyReq.destroyed) proxyReq.end();
  });
});

server.listen(PORT, HOST, () => {
  console.log(`cors-proxy 已启动喵～ http://${HOST}:${PORT}/?url=<url>`);
});