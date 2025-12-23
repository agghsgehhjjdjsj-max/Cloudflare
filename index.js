import { connect } from "cloudflare:sockets";

/**
 * LAST UPDATE
 *  - Wed, 19 November 2025, 04:20 UTC.
 *    https://github.com/NiREvil/zizifn
 */

// Minimal runtime constants used across the worker
const CONST = {
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  ED_PARAMS: {},
};

// small helper used by presets
function generateRandomPath(len = 18) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return "/" + out;
}

// CORE presets for building vless links. Keep values conservative and compatible.
const CORE_PRESETS = {
  xray: {
    tls: {
      path: () => "/",
      security: "tls",
      fp: "chrome",
      alpn: "http/1.1",
      extra: {},
    },
    tcp: {
      path: () => "/",
      security: "none",
      fp: "chrome",
      alpn: undefined,
      extra: {},
    },
  },
  sb: {
    tls: {
      path: () => generateRandomPath(18),
      security: "tls",
      fp: "chrome",
      alpn: "http/1.1",
      extra: CONST.ED_PARAMS,
    },
    tcp: {
      path: () => generateRandomPath(18),
      security: "none",
      fp: "chrome",
      alpn: undefined,
      extra: CONST.ED_PARAMS,
    },
  },
};

// Central configuration defaults and helpers. Keep all secrets/URLs as provided.
const Config = {
  // default user id (kept from existing code comments/usage)
  userID: "d342d11e-d424-4583-b36e-524ab1f0afa4",
  // sensible proxy list placeholder; if env.PROXYIP provided, that will be used in fromEnv
  proxyIPs: ["nima.nscl.ir:443"],
  // Scamalytics credentials preserved from uploaded file
  scamalytics: {
    username: "victoriacrossn",
    apiKey: "ed89b4fef21aba43c15cdd15cff2138dd8d3bbde5aaaa4690ad8e94990448516",
    baseUrl: "https://api12.scamalytics.com/v3/",
  },
  // socks5 defaults
  socks5: {
    enabled: false,
    relayMode: false,
    address: "",
  },

  /**
   * Build runtime config from environment bindings and fallbacks.
   * @param {object} env
   */
  fromEnv(env = {}) {
    const selectedProxyIP = env.PROXYIP || this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
    const [proxyHost, proxyPort = "443"] = (selectedProxyIP || "").split(":");

    return {
      userID: env.UUID || this.userID,
      proxyIP: proxyHost || "",
      proxyPort: proxyPort || "443",
      proxyAddress: selectedProxyIP || proxyHost || "",
      scamalytics: this.scamalytics,
      socks5: this.socks5,
    };
  },
};

/**
 * @param {any} tag
 * @param {string} proto
 */
function makeName(tag, proto) {
  return `${tag}-${proto.toUpperCase()}`;
}

function createVlessLink({
  userID,
  address,
  port,
  host,
  path,
  security,
  sni,
  fp,
  alpn,
  extra = {},
  name,
}) {
  const params = new URLSearchParams({
    type: "ws",
    host,
    path,
  });

  if (security) {
    params.set("security", security);
    if (security === "tls") {
      params.set("allowInsecure", "1");
    }
  }

  if (sni) params.set("sni", sni);
  if (fp) params.set("fp", fp);
  if (alpn) params.set("alpn", alpn);

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === "tls" ? randomizeCase(hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(tag, proto),
  });
}

const pick = (/** @type {string | any[]} */ arr) => arr[Math.floor(Math.random() * arr.length)];

/**
 * @param {Request} request
 * @param {string} core
 * @param {any} userID
 * @param {string} hostName
 */
async function handleIpSubscription(request, core, userID, hostName) {
  const url = new URL(request.url);
  const subName = url.searchParams.get("name");

  /**
   * Cake Subscription usage details
   * - These values create fake usage statistics for subscription clients
   * - Customize these values to display desired traffic and expiry information
   */
  const CAKE_INFO = {
    total_TB: 380, // Total traffic quota in Terabytes
    base_GB: 42000, // Base usage that's always shown (in Gigabytes)
    daily_growth_GB: 250, // Daily traffic growth (in Gigabytes) - simulates gradual usage
    expire_date: "2028-4-20", // Subscription expiry date (YYYY-MM-DD)
  };

  // Domains behind Cloudflare, fixed in the subscription links, you can add as many as you want..
  const mainDomains = [
    hostName,
    "creativecommons.org",
    "www.speedtest.net",
    "sky.rethinkdns.com",
    "cfip.1323123.xyz",
    "cfip.xxxxxxxx.tk",
    "go.inmobi.com",
    "singapore.com",
    "www.visa.com",
    "www.wto.org",
    "cf.090227.xyz",
    "cdnjs.com",
    "zula.ir",
    "csgo.com",
    "fbi.gov",
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096]; // Standard cloudflare TLS/HTTPS ports.
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095]; // Standard cloudflare TCP/HTTP ports.

  let links = [];

  const isPagesDeployment = hostName.endsWith(".pages.dev");

  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: "tls",
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `D${i + 1}`,
      }),
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core,
          proto: "tcp",
          userID,
          hostName,
          address: domain,
          port: pick(httpPorts),
          tag: `D${i + 1}`,
        }),
      );
    }
  });
  

  // Creating cake information headers
  const GB_in_bytes = 1024 * 1024 * 1024;
  const TB_in_bytes = 1024 * GB_in_bytes;

  const total_bytes = CAKE_INFO.total_TB * TB_in_bytes;
  const base_bytes = CAKE_INFO.base_GB * GB_in_bytes;

  // Calculating "dynamic" consumption based on hours per day
  const now = new Date();
  const hours_passed = now.getHours() + now.getMinutes() / 60;
  const daily_growth_bytes = (hours_passed / 24) * (CAKE_INFO.daily_growth_GB * GB_in_bytes);

  // Splitting usage between upload and download
  const cake_download = base_bytes + daily_growth_bytes / 2;
  const cake_upload = base_bytes + daily_growth_bytes / 2;

  // Convert expiration date to Unix Timestamp
  const expire_timestamp = Math.floor(new Date(CAKE_INFO.expire_date).getTime() / 1000);
  const subInfo = `upload=${Math.round(cake_upload)}; download=${Math.round(cake_download)}; total=${total_bytes}; expire=${expire_timestamp}`;

  const headers = {
    "Content-Type": "text/plain;charset=utf-8",
    "Profile-Update-Interval": "6",
    "Subscription-Userinfo": subInfo,
  };

  if (subName) {
    headers["Profile-Title"] = subName;
  }

  const bodyPlain = links.join("\n");
  // Support legacy clients that expect base64: ?format=base64
  if (url.searchParams.get("format") === "base64") {
    const safeB64 = btoa(unescape(encodeURIComponent(bodyPlain)));
    return new Response(safeB64, { headers });
  }

  return new Response(bodyPlain, {
    headers: { ...headers, "Content-Type": "text/plain; charset=utf-8" },
  });
}

export default {
  /**
   * @param {Request<any, CfProperties<any>>} request
   * @param {{ PROXYIP: string; UUID: any; SCAMALYTICS_USERNAME: any; SCAMALYTICS_API_KEY: any; SCAMALYTICS_BASEURL: any; SOCKS5: any; SOCKS5_RELAY: string; }} env
   * @param {any} ctx
   */
  async fetch(request, env, ctx) {
    const cfg = Config.fromEnv(env);
    const url = new URL(request.url);

    // Simple site-level routes: landing (reverse-proxy), robots, security, and root
    if (url.pathname === "/" || url.pathname === "/index.html") {
      return doReverseProxyLanding(request, cfg).catch(() => handleConfigPage(cfg.userID, url.hostname, cfg.proxyAddress));
    }

    if (url.pathname === "/robots.txt") {
      return new Response(getRobotsTxt(), { headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }

    if (url.pathname === "/security.txt") {
      return new Response(getSecurityTxt(cfg), { headers: { "Content-Type": "text/plain; charset=utf-8" } });
    }

    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
      const requestConfig = {
        userID: cfg.userID,
        proxyIP: cfg.proxyIP,
        proxyPort: cfg.proxyPort,
        socks5Address: cfg.socks5.address,
        socks5Relay: cfg.socks5.relayMode,
        enableSocks: cfg.socks5.enabled,
        parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
      };

      return ProtocolOverWSHandler(request, requestConfig);
    }

    if (url.pathname === "/scamalytics-lookup") return handleScamalyticsLookup(request, cfg);

    if (url.pathname.startsWith(`/xray/${cfg.userID}`))
      return handleIpSubscription(request, "xray", cfg.userID, url.hostname);

    if (url.pathname.startsWith(`/sb/${cfg.userID}`))
      return handleIpSubscription(request, "sb", cfg.userID, url.hostname);

    if (url.pathname.startsWith(`/${cfg.userID}`))
      return handleConfigPage(cfg.userID, url.hostname, cfg.proxyAddress);

    // Admin routes
    if (url.pathname === "/admin" || url.pathname === "/admin/login") {
      return handleAdminLogin(request, env, cfg);
    }

    if (url.pathname === "/admin/panel") {
      return handleAdminPanel(request, env, cfg);
    }

    if (url.pathname.startsWith("/admin/api/")) {
      return handleAdminApi(request, env, cfg);
    }

    if (url.pathname === "/user" || url.pathname === "/user/") {
      return handleUserPanel(request, env, cfg);
    }

    return new Response(getCustom404HTML(), { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
  },
  async scheduled(event, env, ctx) {
    try {
      await performHealthCheck(env);
    } catch (e) {
      console.warn('scheduled health check failed', e);
    }
  },
};

/**
 * Try to reverse-proxy the configured `proxyAddress` for the landing page.
 * Falls back to returning the local config page on any error.
 */
async function doReverseProxyLanding(request, cfg) {
  const target = cfg.proxyAddress.startsWith("http") ? cfg.proxyAddress : `https://${cfg.proxyAddress}`;
  try {
    const rp = await fetch(target, { method: request.method, headers: request.headers });
    // Pass through body and selected headers
    const headers = new Headers();
    for (const [k, v] of rp.headers) {
      if (["transfer-encoding", "connection", "keep-alive", "upgrade"].includes(k.toLowerCase())) continue;
      headers.set(k, v);
    }
    // Add a hint for HTTP/3 support
    headers.set("X-Served-By", "Cloudflare-Worker-ReverseProxy");
    return new Response(rp.body, { status: rp.status, headers });
  } catch (e) {
    console.warn("Reverse-proxy landing fetch failed, falling back to local page:", e);
    return handleConfigPage(cfg.userID, (new URL(request.url)).hostname, cfg.proxyAddress);
  }
}

function getRobotsTxt() {
  return `User-agent: *\nDisallow:`;
}

function getSecurityTxt(cfg) {
  return `Contact: mailto:security@${cfg.proxyIP}\nEncryption: https://example.com/pgp-key.txt\nAcknowledgements: https://example.com/hall-of-fame\n`;
}

function getCustom404HTML() {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Not found</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font-family:system-ui,Segoe UI,Arial;margin:40px;color:#222"><h1>404 — Not Found</h1><p>The resource you requested was not found on this edge worker.</p><p>Try the <a href="/">landing page</a> or check your configuration.</p></body></html>`;
}

/**
 * Perform basic health checks against configured proxy address(es).
 * Tries HTTP(S) GET to the configured `cfg.proxyAddress` and `cfg.proxyIP`.
 * If a D1 binding `DB` is available, writes/updates the `proxy_health` table.
 */
async function performHealthCheck(env) {
  const cfg = Config.fromEnv(env);
  const targets = [];
  if (cfg.proxyAddress) targets.push(cfg.proxyAddress.startsWith('http') ? cfg.proxyAddress : `https://${cfg.proxyAddress}`);
  if (cfg.proxyIP) targets.push(cfg.proxyIP.startsWith('http') ? cfg.proxyIP : `https://${cfg.proxyIP}`);
  // also include configured proxyIPs if available on Config
  if (Config.proxyIPs && Array.isArray(Config.proxyIPs)) {
    Config.proxyIPs.forEach((p) => targets.push(p.startsWith('http') ? p : `https://${p}`));
  }

  const results = [];
  for (const t of [...new Set(targets)]) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(t, { method: 'GET', signal: controller.signal });
      clearTimeout(timer);
      results.push({ target: t, ok: res.ok, status: res.status });
    } catch (e) {
      results.push({ target: t, ok: false, error: String(e) });
    }
  }

  // persist to D1 if available
  if (env && env.DB) {
    try {
      await env.DB.prepare("CREATE TABLE IF NOT EXISTS proxy_health (host TEXT PRIMARY KEY, last_checked INTEGER, ok INTEGER, status TEXT)").run();
      for (const r of results) {
        const host = new URL(r.target).host;
        await env.DB.prepare("INSERT OR REPLACE INTO proxy_health (host, last_checked, ok, status) VALUES (?, strftime('%s','now'), ?, ?)").run(host, r.ok ? 1 : 0, r.ok ? String(r.status || 'ok') : (r.error || 'error'));
      }
    } catch (e) {
      console.warn('performHealthCheck: D1 write failed', e);
    }
  }

  return results;
}

/* ---------------------- TOTP Utilities ---------------------- */

function base32ToBytes(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(base32).replace(/=+$/,'').replace(/\s+/g,'').toUpperCase();
  const bytes = [];
  let buffer = 0, bits = 0;
  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean[i]);
    if (val === -1) continue;
    buffer = (buffer << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function timingSafeEqual(a, b) {
  a = String(a);
  b = String(b);
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

async function generateTOTP(secret, timeStep = 30, digits = 6, counterOverride = null) {
  const key = base32ToBytes(secret);
  const epoch = Math.floor(Date.now() / 1000);
  const counter = counterOverride !== null ? counterOverride : Math.floor(epoch / timeStep);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // big-endian write
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    view.setUint8(i, tmp & 0xff);
    tmp = tmp >> 8;
  }
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, counterBuf));
  const offset = sig[sig.length - 1] & 0x0f;
  const code = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  const otp = (code % Math.pow(10, digits)).toString().padStart(digits, '0');
  return otp;
}

async function validateTOTP(secret, token, window = 1, timeStep = 30) {
  const epoch = Math.floor(Date.now() / 1000);
  const counterNow = Math.floor(epoch / timeStep);
  const digits = String(token).length || 6;
  for (let i = -window; i <= window; i++) {
    const otp = await generateTOTP(secret, timeStep, digits, counterNow + i);
    if (timingSafeEqual(String(otp), String(token))) return true;
  }
  return false;
}

/**
 * Performs Scamalytics IP lookup using API.
 * @param {Request} request
 * @param {object} config
 * @returns {Promise<Response>}
 */
async function handleScamalyticsLookup(request, config) {
  const url = new URL(request.url);
  const ipToLookup = url.searchParams.get("ip");
  if (!ipToLookup) {
    return new Response(JSON.stringify({ error: "Missing IP parameter" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const { username, apiKey, baseUrl } = config.scamalytics;
  if (!username || !apiKey) {
    return new Response(JSON.stringify({ error: "Scamalytics API credentials not configured." }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  const scamalyticsUrl = `${baseUrl}${username}/?key=${apiKey}&ip=${ipToLookup}`;
  const headers = new Headers({
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  });

  try {
    const scamalyticsResponse = await fetch(scamalyticsUrl);
    const responseBody = await scamalyticsResponse.json();
    return new Response(JSON.stringify(responseBody), { headers });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.toString() }), {
      status: 500,
      headers,
    });
  }
}

/**
 * @param {any} userID
 * @param {string} hostName
 * @param {string} proxyAddress
 */
function handleConfigPage(userID, hostName, proxyAddress) {
  const html = generateBeautifulConfigPage(userID, hostName, proxyAddress);
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/**
 * @param {any} userID
 * @param {string} hostName
 * @param {string} proxyAddress
 */
function generateBeautifulConfigPage(userID, hostName, proxyAddress) {
  const dream = buildLink({
    core: "xray",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: `${hostName}-Xray`,
  });

  const freedom = buildLink({
    core: "sb",
    proto: "tls",
    userID,
    hostName,
    address: hostName,
    port: 443,
    tag: `${hostName}-Singbox`,
  });

  const subName = "INDEX";
  const configs = { dream, freedom };
  const encodedSubName = encodeURIComponent(subName);

  const subXrayUrl = `https://${hostName}/xray/${userID}?name=${encodedSubName}`;
  const subSbUrl = `https://${hostName}/sb/${userID}?name=${encodedSubName}`;

  const clientUrls = {
    clashMeta: `clash://install-config?url=${encodeURIComponent(`https://revil-sub.pages.dev/sub/clash-meta?url=${subSbUrl}&remote_config=&udp=false&ss_uot=false&show_host=false&forced_ws0rtt=true`)}&name=${encodedSubName}`,
    hiddify: `hiddify://install-config?url=${encodeURIComponent(subXrayUrl)}`,
    v2rayng: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}#${encodedSubName}`,
    exclave: `sn://subscription?url=${encodeURIComponent(subSbUrl)}&name=${encodedSubName}`,
  };

  let finalHTML = `
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>VLESS Proxy Configuration</title>
    <link rel="icon" href="https://raw.githubusercontent.com/NiREvil/zizifn/refs/heads/Legacy/assets/raven-1.png" type="image/png">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300..700&display=swap" rel="stylesheet">
    <style>${getPageCSS()}</style> 
  </head>
  <body data-proxy-ip="${proxyAddress}">
    ${getPageHTML(configs, clientUrls)}
    <script>${getPageScript()}</script>
  </body>
  </html>`;

  return finalHTML;
}

/**
 * Core vless protocol logic
 * Handles VLESS protocol over WebSocket.
 * @param {Request} request
 * @param {object} config
 * @returns {Promise<Response>}
 */
async function ProtocolOverWSHandler(request, config) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  let udpStreamWriter = null;
  const log = (/** @type {string} */ info, /** @type {undefined} */ event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("Sec-WebSocket-Protocol") || "";
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = { value: null };
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWriter) {
            return udpStreamWriter.write(chunk);
          }

          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            addressType,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            ProtocolVersion = new Uint8Array([0, 0]),
            isUDP,
          } = ProcessProtocolHeader(chunk, config.userID);

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp" : "tcp"} `;

          if (hasError) {
            throw new Error(message);
          }

          const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log);
              udpStreamWriter = dnsPipeline.write;
              udpStreamWriter(rawClientData);
            } else {
              throw new Error("UDP proxy is only enabled for DNS (port 53)");
            }
            return;
          }

          HandleTCPOutBound(
            remoteSocketWapper,
            addressType,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log,
            config,
          );
        },
        close() {
          log(`readableWebSocketStream closed`);
        },
        abort(err) {
          log(`readableWebSocketStream aborted`, err);
        },
      }),
    )
    .catch((err) => {
      console.error("Pipeline failed:", err.stack || err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

/**
 * @param {string} uuid
 */
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Helper function to randomize uppercase and lowercase letters in a string
 * @param {string} str Input string (like SNI)
 * @returns {string} String with random characters
 */
function randomizeCase(str) {
  let result = "";
  for (let i = 0; i < str.length; i++) {
    // 50% chance of making a big deal out of it.
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

/**
 * Handles TCP outbound logic for VLESS.
 * @param {{ value: any; }} remoteSocket
 * @param {number} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {any} rawClientData
 * @param {WebSocket} webSocket
 * @param {Uint8Array} protocolResponseHeader
 * @param {{ (info: any, event: any): void; (arg0: string): void; }} log
 * @param {{ socks5Relay: any; parsedSocks5Address: any; enableSocks: any; proxyIP: any; proxyPort: any; userID?: string; socks5Address?: string; }} config
 */
async function HandleTCPOutBound(
  remoteSocket,
  addressType,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config,
) {
  if (!config) {
    config = {
      userID: "d342d11e-d424-4583-b36e-524ab1f0afa4",
      socks5Address: "",
      socks5Relay: false,
      proxyIP: "nima.nscl.ir",
      proxyPort: "443",
      enableSocks: false,
      parsedSocks5Address: {},
    };
  }

  /**
   * @param {string} address
   * @param {number} port
   */
  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = config.enableSocks
      ? await connectAndWrite(addressRemote, portRemote, true)
      : await connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false,
        );

    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
}

/**
 * Converts WebSocket messages to a readable stream.
 * @param {WebSocket} webSocketServer
 * @param {string} earlyDataHeader
 * @param {{ (info: any, event: any): void; (arg0: string): void; }} log
 */
function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (/** @type {{ data: any; }} */ event) => {
        const data = event.data;
        try {
          if (typeof data === "string") {
            controller.enqueue(new TextEncoder().encode(data).buffer);
          } else if (data instanceof ArrayBuffer) {
            controller.enqueue(data);
          } else if (ArrayBuffer.isView(data)) {
            controller.enqueue(data.buffer);
          } else if (data && typeof data.arrayBuffer === "function") {
            // Blob or similar
            data.arrayBuffer().then((buf) => controller.enqueue(buf)).catch((err) => controller.error(err));
          } else {
            // Fallback: try to coerce to string then to buffer
            controller.enqueue(new TextEncoder().encode(String(data)).buffer);
          }
        } catch (err) {
          controller.error(err);
        }
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (/** @type {any} */ err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        console.warn('Early WebSocket pre-data parse failed, ignoring early data:', error);
      } else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) {},
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

/**
 * Parses and validates VLESS protocol header.
 * @param {ArrayBufferLike & { BYTES_PER_ELEMENT?: never; }} protocolBuffer
 * @param {string} userID
 */
function ProcessProtocolHeader(protocolBuffer, userID) {
  // Minimum header size: version(1) + uuid(16) + optlen(1) + command(1) + port(2) + addrType(1)
  if (!(protocolBuffer && protocolBuffer.byteLength >= 22))
    return { hasError: true, message: "invalid data: too short" };

  const dataView = new DataView(protocolBuffer);
  const version = dataView.getUint8(0);

  // Safely read UUID bytes (1..16)
  let slicedBufferString;
  try {
    const uuidBytes = new Uint8Array(protocolBuffer.slice(1, 17));
    slicedBufferString = unsafeStringify(uuidBytes, 0);
  } catch (e) {
    return { hasError: true, message: "invalid user (uuid parsing)" };
  }

  const uuids = String(userID || "").split(",").map((id) => id.trim()).filter(Boolean);
  if (uuids.length === 0) return { hasError: true, message: "no configured users" };
  const isValidUser = uuids.some((uuid) => uuid.toLowerCase() === slicedBufferString.toLowerCase());
  if (!isValidUser) return { hasError: true, message: "invalid user" };

  const optLength = dataView.getUint8(17);
  const commandPos = 18 + optLength; // command is at this offset
  if (protocolBuffer.byteLength <= commandPos)
    return { hasError: true, message: "invalid data: missing command" };

  const command = dataView.getUint8(commandPos);
  if (command !== 1 && command !== 2)
    return { hasError: true, message: `command ${command} is not supported` };

  const portPos = commandPos + 1; // port starts here (2 bytes)
  if (protocolBuffer.byteLength < portPos + 2)
    return { hasError: true, message: "invalid data: missing port" };

  const portRemote = dataView.getUint16(portPos); // big-endian network order
  const addrTypePos = portPos + 2;
  if (protocolBuffer.byteLength <= addrTypePos)
    return { hasError: true, message: "invalid data: missing address type" };

  const addressType = dataView.getUint8(addrTypePos);
  let addressValue = "";
  let rawDataIndex = addrTypePos + 1;

  // Mapping used here follows earlier script: 1=IPv4, 2=Domain, 3=IPv6
  if (addressType === 1) {
    // IPv4 (4 bytes)
    if (protocolBuffer.byteLength < rawDataIndex + 4) return { hasError: true, message: "invalid data: IPv4 truncated" };
    const octets = [];
    for (let i = 0; i < 4; i++) octets.push(dataView.getUint8(rawDataIndex + i));
    addressValue = octets.join(".");
    rawDataIndex += 4;
  } else if (addressType === 2) {
    // Domain: first byte = length
    if (protocolBuffer.byteLength < rawDataIndex + 1) return { hasError: true, message: "invalid data: domain length missing" };
    const domainLen = dataView.getUint8(rawDataIndex);
    rawDataIndex += 1;
    if (protocolBuffer.byteLength < rawDataIndex + domainLen) return { hasError: true, message: "invalid data: domain truncated" };
    addressValue = new TextDecoder().decode(protocolBuffer.slice(rawDataIndex, rawDataIndex + domainLen));
    rawDataIndex += domainLen;
  } else if (addressType === 3) {
    // IPv6 (16 bytes)
    if (protocolBuffer.byteLength < rawDataIndex + 16) return { hasError: true, message: "invalid data: IPv6 truncated" };
    const parts = [];
    for (let i = 0; i < 8; i++) {
      const part = dataView.getUint16(rawDataIndex + i * 2).toString(16);
      parts.push(part);
    }
    addressValue = parts.join(":" );
    rawDataIndex += 16;
  } else {
    return { hasError: true, message: `invalid addressType: ${addressType}` };
  }

  if (!addressValue) return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex,
    ProtocolVersion: new Uint8Array([version]),
    isUDP: command === 2,
  };
}

/**
 * Pipes remote socket data to WebSocket.
 * @param {Socket} remoteSocket
 * @param {WebSocket} webSocket
 * @param {string | Uint8Array | ArrayBuffer | ArrayBufferView | Blob} protocolResponseHeader
 * @param {{ (): Promise<void>; (): any; }} retry
 * @param {{ (info: any, event: any): void; (arg0: string): void; (info: any, event: any): void; (arg0: string): void; (arg0: string): void; }} log
 */
async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
            throw new Error("WebSocket is not open");
          hasIncomingData = true;
          const dataToSend = protocolResponseHeader
            ? await new Blob([protocolResponseHeader, chunk]).arrayBuffer()
            : chunk;
          webSocket.send(dataToSend);
          protocolResponseHeader = null;
        },
        close() {
          log(`Remote connection readable closed. Had incoming data: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`Remote connection readable aborted:`, reason);
        },
      }),
    );
  } catch (error) {
    console.error(`RemoteSocketToWS error:`, error.stack || error);
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    log(`No incoming data, retrying`);
    await retry();
  }
}

/**
 * decodes base64 string to ArrayBuffer.
 * @param {string} base64Str
 */
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    // Tolerate URL-safe base64 and whitespace
    const cleaned = base64Str.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    // Pad base64 if missing padding
    const pad = cleaned.length % 4;
    const padded = pad === 0 ? cleaned : cleaned + "=".repeat(4 - pad);
    const binaryStr = atob(padded);
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) view[i] = binaryStr.charCodeAt(i);
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

/**
 * Safely closes a WebSocket connection.
 * @param {{ readyState: number; close: () => void; }} socket
 */
function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error:", error);
  }
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

/*
 * @param {Uint8Array | (string | number)[]} arr
 */
function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

/*
 * @param {Uint8Array} arr
 */
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError("Stringified UUID is invalid");
  return uuid;
}

/**
 * DNS pipeline for UDP DNS requests, using DNS-over-HTTPS, (REvil Method).
 * @param {WebSocket} webSocket
 * @param {Uint8Array} vlessResponseHeader
 * @param {Function} log
 * @returns {Promise<{write: Function}>}
 */
async function createDnsPipeline(webSocket, vlessResponseHeader, log) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      // Parse UDP packets from VLESS framing
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            // Send DNS query using DoH
            const resp = await fetch(`https://1.1.1.1/dns-query`, {
              method: "POST",
              headers: { "content-type": "application/dns-message" },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(`DNS query successful, length: ${udpSize}`);
              if (isHeaderSent) {
                webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              } else {
                webSocket.send(
                  await new Blob([
                    vlessResponseHeader,
                    udpSizeBuffer,
                    dnsQueryResult,
                  ]).arrayBuffer(),
                );
                isHeaderSent = true;
              }
            }
          } catch (error) {
            log("DNS query error: " + error);
          }
        },
      }),
    )
    .catch((e) => {
      log("DNS stream error: " + e);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: (/** @type {any} */ chunk) => writer.write(chunk),
  };
}

/**
 * SOCKS5 TCP connection logic.
 * @param {any} addressType
 * @param {string} addressRemote
 * @param {number} portRemote
 * @param {any} log
 * @param {{ username: any; password: any; hostname: any; port: any; }} parsedSocks5Addr
 */
async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Addr) {
  const { username, password, hostname, port } = parsedSocks5Addr;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();

  await writer.write(new Uint8Array([5, 2, 0, 2])); // SOCKS5 greeting
  let res = (await reader.read()).value;
  if (res[0] !== 0x05 || res[1] === 0xff) throw new Error("SOCKS5 server connection failed.");

  if (res[1] === 0x02) {
    // Auth required
    if (!username || !password) throw new Error("SOCKS5 auth credentials not provided.");
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password),
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 0x01 || res[1] !== 0x00) throw new Error("SOCKS5 authentication failed.");
  }

  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array([1, ...addressRemote.split(".").map(Number)]);
      break;
    case 2:
      DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
      break;
    case 3:
      DSTADDR = new Uint8Array([
        4,
        ...addressRemote
          .split(":")
          .flatMap((/** @type {string} */ x) => [
            parseInt(x.slice(0, 2), 16),
            parseInt(x.slice(2), 16),
          ]),
      ]);
      break;
    default:
      throw new Error(`Invalid addressType for SOCKS5: ${addressType}`);
  }

  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (res[1] !== 0x00) throw new Error("Failed to open SOCKS5 connection.");

  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

/**
 * Parses SOCKS5 address string.
 * @param {string} address
 * @returns {object}
 */
function socks5AddressParser(address) {
  try {
    const [authPart, hostPart] = address.includes("@") ? address.split("@") : [null, address];
    const [hostname, portStr] = hostPart.split(":");
    const port = parseInt(portStr, 10);
    if (!hostname || isNaN(port)) throw new Error();

    let username, password;
    if (authPart) {
      [username, password] = authPart.split(":");
      if (!username) throw new Error();
    }
    return { username, password, hostname, port };
  } catch {
    throw new Error("Invalid SOCKS5 address format. Expected [user:pass@]host:port");
  }
}

/**
 * @returns {string} CSS content of the page.
 */
function getPageCSS() {
  return `
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  @font-face {
    font-family: "Aldine 401 BT Web";
    src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/Aldine401_Mersedeh.woff2") format("woff2");
    font-weight: 400; font-style: normal; font-display: swap;
  }
  @font-face {
    font-family: "Styrene B LC";
    src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Regular.woff2") format("woff2");
    font-weight: 400; font-style: normal; font-display: swap;
  }
  @font-face {
    font-family: "Styrene B LC";
    src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Medium.woff2") format("woff2");
    font-weight: 500; font-style: normal; font-display: swap;
  }

  :root {
    --background-primary: #2a2421; --background-secondary: #35302c; --background-tertiary: #413b35;
    --border-color: #5a4f45; --border-color-hover: #766a5f; --text-primary: #e5dfd6; --text-secondary: #b3a89d;
    --text-accent: #ffffff; --accent-primary: #be9b7b; --accent-secondary: #d4b595; --accent-tertiary: #8d6e5c;
    --accent-primary-darker: #8a6f56; --button-text-primary: #2a2421; --button-text-secondary: var(--text-primary);
    --shadow-color: rgba(0, 0, 0, 0.35); --shadow-color-accent: rgba(190, 155, 123, 0.4);
    --border-radius: 8px; --transition-speed: 0.2s; --transition-speed-fast: 0.1s; --transition-speed-medium: 0.3s; --transition-speed-long: 0.6s;
    --status-success: #70b570; --status-error: #e05d44; --status-warning: #e0bc44; --status-info: #4f90c4;
    --serif: "Aldine 401 BT Web", "Times New Roman", Times, Georgia, ui-serif, serif;
    --sans-serif: "Styrene B LC", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, "Noto Color Emoji", sans-serif;
    --mono-serif: "Fira Code", Cantarell, "Courier Prime", monospace;
  }

  body {
    font-family: var(--sans-serif); font-size: 16px; font-weight: 400; font-style: normal;
    background-color: var(--background-primary); color: var(--text-primary);
    padding: 3rem; line-height: 1.5; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
  }

  .container {
    max-width: 800px; margin: 20px auto; padding: 0 12px; border-radius: var(--border-radius);
    box-shadow: 0 6px 15px rgba(0, 0, 0, 0.2), 0 0 25px 8px var(--shadow-color-accent);
    transition: box-shadow var(--transition-speed-medium) ease;
  }

  .container:hover { box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25), 0 0 35px 10px var(--shadow-color-accent); }
  .header { text-align: center; margin-bottom: 40px; padding-top: 30px; }
  .header h1 { font-family: var(--serif); font-weight: 400; font-size: 2rem; color: var(--text-accent); margin-top: 0px; margin-bottom: 2px; }
  .header p { color: var(--text-secondary); font-size: 0.8rem; font-weight: 400; }
  .config-card {
    background: var(--background-secondary); border-radius: var(--border-radius); padding: 20px; margin-bottom: 24px;
    border: 1px solid var(--border-color);
    transition: border-color var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
  }

  .config-card:hover { border-color: var(--border-color-hover); box-shadow: 0 4px 8px var(--shadow-color); }
  .config-title {
    font-family: var(--serif); font-size: 1.4rem; font-weight: 400; color: var(--accent-secondary);
    margin-bottom: 16px; padding-bottom: 13px; border-bottom: 1px solid var(--border-color);
    display: flex; align-items: center; justify-content: space-between;
  }

  .config-title .refresh-btn {
    position: relative; overflow: hidden; display: flex; align-items: center; gap: 4px;
    font-family: var(--serif); font-size: 12px; padding: 6px 12px; border-radius: 6px;
    color: var(--accent-secondary); background-color: var(--background-tertiary); border: 1px solid var(--border-color);
    cursor: pointer;
    transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
  }

  .config-title .refresh-btn::before {
    content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);
    transform: translateX(-100%); transition: transform var(--transition-speed-long) ease; z-index: 1;
  }

  .config-title .refresh-btn:hover {
    letter-spacing: 0.5px; font-weight: 600; background-color: #4d453e; color: var(--accent-primary);
    border-color: var(--border-color-hover); transform: translateY(-2px); box-shadow: 0 4px 8px var(--shadow-color);
  }

  .config-title .refresh-btn:hover::before { transform: translateX(100%); }
  .config-title .refresh-btn:active { transform: translateY(0px) scale(0.98); box-shadow: none; }
  .refresh-icon { width: 12px; height: 12px; stroke: currentColor; }
  .config-content {
    position: relative; background: var(--background-tertiary); border-radius: var(--border-radius);
    padding: 16px; margin-bottom: 20px; border: 1px solid var(--border-color);
  }

  .config-content pre {
    overflow-x: auto; font-family: var(--mono-serif); font-size: 12px; color: var(--text-primary);
    margin: 0; white-space: pre-wrap; word-break: break-all;
  }

  .button {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 8px 16px; border-radius: var(--border-radius); font-size: 15px; font-weight: 500;
    cursor: pointer; border: 1px solid var(--border-color); background-color: var(--background-tertiary);
    color: var(--button-text-secondary);
    transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
    -webkit-tap-highlight-color: transparent; touch-action: manipulation; text-decoration: none; overflow: hidden; z-index: 1;
  }

  .button:focus-visible { outline: 2px solid var(--accent-primary); outline-offset: 2px; }
  .button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; transition: opacity var(--transition-speed) ease; }
  .copy-buttons {
    position: relative; display: flex; gap: 4px; overflow: hidden; align-self: center;
    font-family: var(--serif); font-size: 13px; padding: 6px 12px; border-radius: 6px;
    color: var(--accent-secondary); border: 1px solid var(--border-color);
    transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
  }

  .copy-buttons::before, .client-btn::before {
    content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
    background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);
    transform: translateX(-100%); transition: transform var(--transition-speed-long) ease; z-index: -1;
  }

  .copy-buttons:hover::before, .client-btn:hover::before { transform: translateX(100%); }
  .copy-buttons:hover {
    background-color: #4d453e; letter-spacing: 0.5px; font-weight: 600;
    border-color: var(--border-color-hover); transform: translateY(-2px); box-shadow: 0 4px 8px var(--shadow-color);
  }

  .copy-buttons:active { transform: translateY(0px) scale(0.98); box-shadow: none; }
  .copy-icon { width: 12px; height: 12px; stroke: currentColor; }
  .client-buttons { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-top: 16px; }
  .client-btn {
    width: 100%; background-color: var(--accent-primary); color: var(--background-tertiary);
    border-radius: 6px; border-color: var(--accent-primary-darker); position: relative; overflow: hidden;
    transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1); box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15);
  }

  .client-btn::after {
    content: ''; position: absolute; bottom: -5px; left: 0; width: 100%; height: 5px;
    background: linear-gradient(90deg, var(--accent-tertiary), var(--accent-secondary));
    opacity: 0; transition: all 0.3s ease; z-index: 0;
  }

  .client-btn:hover {
    text-transform: uppercase; letter-spacing: 0.3px; transform: translateY(-3px);
    background-color: var(--accent-secondary); color: var(--button-text-primary);
    box-shadow: 0 5px 15px rgba(190, 155, 123, 0.5); border-color: var(--accent-secondary);
  }

  .client-btn:hover::after { opacity: 1; bottom: 0; }
  .client-btn:active { transform: translateY(0) scale(0.98); box-shadow: 0 2px 3px rgba(0, 0, 0, 0.2); background-color: var(--accent-primary-darker); }
  .client-btn .client-icon { position: relative; z-index: 2; transition: transform 0.3s ease; }
  .client-btn:hover .client-icon { transform: rotate(15deg) scale(1.1); }
  .client-btn .button-text { position: relative; z-index: 2; transition: letter-spacing 0.3s ease; }
  .client-btn:hover .button-text { letter-spacing: 0.5px; }
  .client-icon { width: 18px; height: 18px; border-radius: 6px; background-color: var(--background-secondary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .client-icon svg { width: 14px; height: 14px; fill: var(--accent-secondary); }
  .button.copied { background-color: var(--accent-secondary) !important; color: var(--background-tertiary) !important; }
  .button.error { background-color: #c74a3b !important; color: var(--text-accent) !important; }

  .footer { text-align: center; margin-top: 20px; padding-bottom: 40px; color: var(--text-secondary); font-size: 12px; }
  .footer p { margin-bottom: 0px; }

  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: var(--background-primary); border-radius: 4px; }
  ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; border: 2px solid var(--background-primary); }
  ::-webkit-scrollbar-thumb:hover { background: var(--border-color-hover); }
  * { scrollbar-width: thin; scrollbar-color: var(--border-color) var(--background-primary); }

  .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 24px; }
  .ip-info-section { background-color: var(--background-tertiary); border-radius: var(--border-radius); padding: 16px; border: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 20px; }
  .ip-info-header { display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }
  .ip-info-header svg { width: 20px; height: 20px; stroke: var(--accent-secondary); }
  .ip-info-header h3 { font-family: var(--serif); font-size: 18px; font-weight: 400; color: var(--accent-secondary); margin: 0; }
  .ip-info-content { display: flex; flex-direction: column; gap: 10px; }
  .ip-info-item { display: flex; flex-direction: column; gap: 2px; }
  .ip-info-item .label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
  .ip-info-item .value { font-size: 14px; color: var(--text-primary); word-break: break-all; line-height: 1.4; }

  .badge { display: inline-flex; align-items: center; justify-content: center; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge-yes { background-color: rgba(112, 181, 112, 0.15); color: var(--status-success); border: 1px solid rgba(112, 181, 112, 0.3); }
  .badge-no { background-color: rgba(224, 93, 68, 0.15); color: var(--status-error); border: 1px solid rgba(224, 93, 68, 0.3); }
  .badge-neutral { background-color: rgba(79, 144, 196, 0.15); color: var(--status-info); border: 1px solid rgba(79, 144, 196, 0.3); }
  .badge-warning { background-color: rgba(224, 188, 68, 0.15); color: var(--status-warning); border: 1px solid rgba(224, 188, 68, 0.3); }
  .skeleton { display: block; background: linear-gradient(90deg, var(--background-tertiary) 25%, var(--background-secondary) 50%, var(--background-tertiary) 75%); background-size: 200% 100%; animation: loading 1.5s infinite; border-radius: 4px; height: 16px; }
  @keyframes loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
  .country-flag { display: inline-block; width: 18px; height: auto; max-height: 14px; margin-right: 6px; vertical-align: middle; border-radius: 2px; }

  .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.7); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; visibility: hidden; transition: opacity 0.3s ease, visibility 0.3s ease; }
  .modal-overlay.visible { opacity: 1; visibility: visible; }
  .modal-overlay.visible { opacity: 1; visibility: visible; }
  .modal-content { background: var(--background-secondary); padding: 24px; border-radius: var(--border-radius); border: 1px solid var(--border-color); width: 90%; max-width: 450px; text-align: center; box-shadow: 0 8px 30px var(--shadow-color-accent); transform: scale(0.95); transition: transform 0.3s ease; }
  .modal-overlay.visible .modal-content { transform: scale(1); }
  .modal-title { font-family: var(--serif); font-size: 1.5rem; color: var(--accent-secondary); margin-bottom: 16px; }
  .modal-text { color: var(--text-primary); font-size: 14px; line-height: 1.6; margin-bottom: 20px; }
  .modal-instruction { background: var(--background-tertiary); padding: 12px; border-radius: 6px; margin-bottom: 24px; font-size: 13px; line-height: 1.8; border: 1px solid var(--border-color); }
  .modal-instruction code { background: var(--background-primary); color: var(--accent-primary); padding: 3px 6px; border-radius: 4px; font-family: var(--mono-serif); }
  #hiddify-modal-continue { width: 100%;}

  @media (max-width: 768px) {
    body { padding: 20px; } .container { padding: 0 14px; width: min(100%, 768px); }
    .ip-info-grid { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 18px; }
    .header h1 { font-size: 1.8rem; } .header p { font-size: 0.7rem }
    .ip-info-section { padding: 14px; gap: 18px; } .ip-info-header h3 { font-size: 16px; }
    .ip-info-header { gap: 8px; } .ip-info-content { gap: 8px; }
    .ip-info-item .label { font-size: 11px; } .ip-info-item .value { font-size: 13px; }
    .config-card { padding: 16px; } .config-title { font-size: 18px; }
    .config-title .refresh-btn { font-size: 11px; } .config-content pre { font-size: 12px; }
    .client-buttons { grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); }
    .button { font-size: 12px; } .copy-buttons { font-size: 11px; }
  }

  @media (max-width: 480px) {
    body { padding: 16px; } .container { padding: 0 12px; width: min(100%, 390px); }
    .header h1 { font-size: 20px; } .header p { font-size: 8px; }
    .ip-info-section { padding: 14px; gap: 16px; }
    .ip-info-grid { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
    .ip-info-header h3 { font-size: 14px; } .ip-info-header { gap: 6px; }
    .ip-info-content { gap: 6px; } .ip-info-header svg { width: 18px; height: 18px; }
    .ip-info-item .label { font-size: 9px; } .ip-info-item .value { font-size: 11px; }
    .badge { padding: 2px 6px; font-size: 10px; border-radius: 10px; }
    .config-card { padding: 10px; } .config-title { font-size: 16px; }
    .config-title .refresh-btn { font-size: 10px; } .config-content { padding: 12px; }
    .config-content pre { font-size: 10px; }
    .client-buttons { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
    .button { padding: 4px 8px; font-size: 11px; } .copy-buttons { font-size: 10px; }
    .footer { font-size: 10px; }
  }

  @media (max-width: 359px) {
    body { padding: 12px; font-size: 14px; } .container { max-width: 100%; padding: 8px; }
    .header h1 { font-size: 16px; } .header p { font-size: 6px; }
    .ip-info-section { padding: 12px; gap: 12px; }
    .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
    .ip-info-header h3 { font-size: 13px; } .ip-info-header { gap: 4px; } .ip-info-content { gap: 4px; }
    .ip-info-header svg { width: 16px; height: 16px; } .ip-info-item .label { font-size: 8px; }
    .ip-info-item .value { font-size: 10px; } .badge { padding: 1px 4px; font-size: 9px; border-radius: 8px; }
    .config-card { padding: 8px; } .config-title { font-size: 13px; } .config-title .refresh-btn { font-size: 9px; }
    .config-content { padding: 8px; } .config-content pre { font-size: 8px; }
    .client-buttons { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
    .button { padding: 3px 6px; font-size: 10px; } .copy-buttons { font-size: 9px; } .footer { font-size: 8px; }
  }
    @media (min-width: 360px) { .container { max-width: 95%; } }
    @media (min-width: 480px) { .container { max-width: 90%; } }
    @media (min-width: 640px) { .container { max-width: 600px; } }
    @media (min-width: 768px) { .container { max-width: 720px; } }
    @media (min-width: 1024px) { .container { max-width: 800px; } }
  `;
}

/**
 * @param {object} configs - Object containing configuration links.
 * @param {object} clientUrls - Object containing client URLs.
 * @returns {string} The HTML body content of the page.
 */
function getPageHTML(configs, clientUrls) {
  return `
    <div class="container">
    <div class="header">
      <h1>VLESS Proxy Configuration</h1>
      <p>Copy the configuration or import directly into your client</p>
    </div>

    <div class="config-card">
      <div class="config-title">
        <span>Network Information</span>
        <button id="refresh-ip-info" class="refresh-btn" aria-label="Refresh IP information">
          <svg
            class="refresh-icon"
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <path
              d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"
            />
          </svg>
          Refresh
        </button>
      </div>
      <div class="ip-info-grid">
        <div class="ip-info-section">
          <div class="ip-info-header">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path
                d="M15.5 2H8.6c-.4 0-.8.2-1.1.5-.3.3-.5.7-.5 1.1v16.8c0 .4.2.8.5 1.1.3.3.7.5 1.1.5h6.9c.4 0 .8-.2 1.1-.5.3-.3.5-.7.5-1.1V3.6c0-.4-.2-.8-.5-1.1-.3-.3-.7-.5-1.1-.5z"
              />
              <circle cx="12" cy="18" r="1" />
            </svg>
            <h3>Proxy Server</h3>
          </div>
          <div class="ip-info-content">
            <div class="ip-info-item">
              <span class="label">Proxy Host</span
              ><span class="value" id="proxy-host"
                ><span class="skeleton" style="width: 150px"></span
              ></span>
            </div>
            <div class="ip-info-item">
              <span class="label">IP Address</span
              ><span class="value" id="proxy-ip"
                ><span class="skeleton" style="width: 120px"></span
              ></span>
            </div>
            <div class="ip-info-item">
              <span class="label">Location</span
              ><span class="value" id="proxy-location"
                ><span class="skeleton" style="width: 100px"></span
              ></span>
            </div>
            <div class="ip-info-item">
              <span class="label">ISP Provider</span
              ><span class="value" id="proxy-isp"
                ><span class="skeleton" style="width: 140px"></span
              ></span>
            </div>
          </div>
        </div>
        <div class="ip-info-section">
          <div class="ip-info-header">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            >
              <path
                d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16"
              />
            </svg>
            <h3>Your Connection</h3>
          </div>
          <div class="ip-info-content">
            <div class="ip-info-item">
              <span class="label">Your IP</span
              ><span class="value" id="client-ip"
                ><span class="skeleton" style="width: 110px"></span
              ></span>
            </div>
            <div class="ip-info-item">
              <span class="label">Location</span
              ><span class="value" id="client-location"
                ><span class="skeleton" style="width: 90px"></span
              ></span>
            </div>
            <div class="ip-info-item">
              <span class="label">ISP Provider</span
              ><span class="value" id="client-isp"
                ><span class="skeleton" style="width: 130px"></span
              ></span>
            </div>
            <div class="ip-info-item">
              <span class="label">Risk Score</span
              ><span class="value" id="client-proxy"
                ><span class="skeleton" style="width: 100px"></span
              ></span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="config-card">
      <div class="config-title">
        <span>Xray Core Clients</span>
        <button class="button copy-buttons" onclick="copyToClipboard(this, '${configs.dream}')">
          <svg
            class="copy-icon"
            xmlns="http://www.w3.org/2000/svg"
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Copy
        </button>
      </div>
      <div class="config-content"><pre id="xray-config">${configs.dream}</pre></div>
      <div class="client-buttons">
        <a href="${clientUrls.hiddify}" id="hiddify-import-btn" class="button client-btn">
          <span class="client-icon"
            ><svg viewBox="0 0 24 24">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" /></svg
          ></span>
          <span class="button-text">Import to Hiddify</span>
        </a>
        <a href="${clientUrls.v2rayng}" class="button client-btn">
          <span class="client-icon"
            ><svg viewBox="0 0 24 24">
              <path d="M12 2L4 5v6c0 5.5 3.5 10.7 8 12.3 4.5-1.6 8-6.8 8-12.3V5l-8-3z" /></svg
          ></span>
          <span class="button-text">Import to V2rayNG</span>
        </a>
      </div>
    </div>

    <div class="config-card">
      <div class="config-title">
        <span>Sing-Box Core Clients</span>
        <button class="button copy-buttons" onclick="copyToClipboard(this, '${configs.freedom}')">
          <svg
            class="copy-icon"
            xmlns="http://www.w3.org/2000/svg"
            width="12"
            height="12"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          >
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
          Copy
        </button>
      </div>
      <div class="config-content"><pre id="singbox-config">${configs.freedom}</pre></div>
      <div class="client-buttons">
        <a href="${clientUrls.clashMeta}" class="button client-btn">
          <span class="client-icon"
            ><svg viewBox="0 0 24 24">
              <path
                d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"
              /></svg
          ></span>
          <span class="button-text">Import to Clash Meta</span>
        </a>
        <a href="${clientUrls.exclave}" class="button client-btn">
          <span class="client-icon"
            ><svg viewBox="0 0 24 24">
              <path
                d="M20,8h-3V6c0-1.1-0.9-2-2-2H9C7.9,4,7,4.9,7,6v2H4C2.9,8,2,8.9,2,10v9c0,1.1,0.9,2,2,2h16c1.1,0,2-0.9,2-2v-9 C22,8.9,21.1,8,20,8z M9,6h6v2H9V6z M20,19H4v-2h16V19z M20,15H4v-5h3v1c0,0.55,0.45,1,1,1h1.5c0.28,0,0.5-0.22,0.5-0.5v-0.5h4v0.5 c0,0.28,0.22,0.5,0.5,0.5H16c0.55,0,1-0.45,1-1v-1h3V15z"
              />
              <circle cx="8.5" cy="13.5" r="1" />
              <circle cx="15.5" cy="13.5" r="1" />
              <path d="M12,15.5c-0.55,0-1-0.45-1-1h2C13,15.05,12.55,15.5,12,15.5z" /></svg
          ></span>
          <span class="button-text">Import to Exclave</span>
        </a>
      </div>
    </div>

    <div class="footer">
      <p>
        © <span id="current-year">${new Date().getFullYear()}</span> REvil - All Rights Reserved
      </p>
      <p>Secure. Private. Fast.</p>
    </div>
  </div>

  <div id="hiddify-dns-modal" class="modal-overlay" style="display: none">
    <div class="modal-content">
      <h3 class="modal-title">Important Note for Hiddify Users</h3>
      <p class="modal-text">
        For the configuration to work correctly, you need to change the
        <strong>Remote DNS</strong> setting in the Hiddify app.
      </p>
      <div class="modal-instruction">
        Change from: <code>udp://1.1.1.1</code><br />
        To: <code>https://8.8.8.8/dns-query</code>
      </div>
      <button id="hiddify-modal-continue" class="button client-btn">Continue to Hiddify</button>
    </div>
  </div>
  `;
}

/**
 * @returns {string} Client-side JavaScript
 * This function is self-contained and doesn't need template literals from the server.
 * Using a template literal here is just for multi-line string formatting.
 */
function getPageScript() {
  return `
      function copyToClipboard(button, text) {
        const originalHTML = button.innerHTML;
        navigator.clipboard.writeText(text).then(() => {
          button.innerHTML = \`<svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copied!\`;
          button.classList.add("copied");
          button.disabled = true;
          setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove("copied");
            button.disabled = false;
          }, 1200);
        }).catch(err => {
          console.error("Failed to copy text: ", err);
        });
      }

      async function fetchClientPublicIP() {
        try {
          const response = await fetch('https://api.ipify.org?format=json');
          if (!response.ok) throw new Error(\`HTTP error! status: \${response.status}\`);
          return (await response.json()).ip;
        } catch (error) {
          console.error('Error fetching client IP:', error);
          return null;
        }
      }

      async function fetchScamalyticsClientInfo(clientIp) {
        if (!clientIp) return null;
        try {
          const response = await fetch(\`/scamalytics-lookup?ip=\${encodeURIComponent(clientIp)}\`);
          if (!response.ok) {
            const errorText = await response.text();
            throw new Error(\`Worker request failed! status: \${response.status}, details: \${errorText}\`);
          }
          const data = await response.json();
          if (data.scamalytics && data.scamalytics.status === 'error') {
              throw new Error(data.scamalytics.error || 'Scamalytics API error via Worker');
          }
          return data;
        } catch (error) {
          console.error('Error fetching from Scamalytics via Worker:', error);
          return null;
        }
      }

      // Extract information from IP databases
      function updateScamalyticsClientDisplay(data) {
        const prefix = 'client';
        if (!data || !data.scamalytics || data.scamalytics.status !== 'ok') {
          showError(prefix, (data && data.scamalytics && data.scamalytics.error) || 'Could not load client data from Scamalytics');
          return;
        }

        const sa = data.scamalytics;
        const ext = data.external_datasources || {};

        // Alternative sources for extracting information
        const ipinfo = ext.ipinfo || {};
        const maxmind = ext.maxmind_geolite2 || {};
        const dbip = ext.dbip || {};

        const elements = {
          ip: document.getElementById(\`\${prefix}-ip\`),
          location: document.getElementById(\`\${prefix}-location\`),
          isp: document.getElementById(\`\${prefix}-isp\`),
          proxy: document.getElementById(\`\${prefix}-proxy\`)
        };

        // Helper function for data validation
        const isValid = (val) => val && val !== "PREMIUM FIELD - upgrade to view" && val.trim() !== "";

        // IP display (Your connection)
        if (elements.ip) elements.ip.textContent = sa.ip || "N/A";

        // Show ISP - priority is given to ipinfo
        let ispName = "N/A";
        if (isValid(ipinfo.as_name)) ispName = ipinfo.as_name;
        else if (isValid(maxmind.as_name)) ispName = maxmind.as_name;
        else if (isValid(sa.scamalytics_isp)) ispName = sa.scamalytics_isp;
        else if (isValid(dbip.isp_name)) ispName = dbip.isp_name;

        if (elements.isp) elements.isp.textContent = ispName;

        // Show location (city and country)
        if (elements.location) {
          let city = "";
          let countryName = "";
          let countryCode = "";

          // Trying to find a city
          if (isValid(maxmind.ip_city)) city = maxmind.ip_city;
          else if (isValid(dbip.ip_city)) city = dbip.ip_city;

          // Trying to find a country
          if (isValid(ipinfo.ip_country_name)) {
             countryName = ipinfo.ip_country_name;
             countryCode = ipinfo.ip_country_code;
          } else if (isValid(maxmind.ip_country_name)) {
             countryName = maxmind.ip_country_name;
             countryCode = maxmind.ip_country_code;
          } else if (isValid(dbip.ip_country_name)) {
             countryName = dbip.ip_country_name;
             countryCode = dbip.ip_country_code;
          }

          countryCode = countryCode ? countryCode.toLowerCase() : '';

          let flagElementHtml = countryCode ? \`<img src="https://flagcdn.com/w20/\${countryCode}.png" srcset="https://flagcdn.com/w40/\${countryCode}.png 2x" alt="\${countryCode}" class="country-flag"> \` : '';
          let textPart = [city, countryName].filter(Boolean).join(', ');

          elements.location.innerHTML = (flagElementHtml || textPart) ? \`\${flagElementHtml}\${textPart}\`.trim() : "N/A";
        }

        // Show risk score
        if (elements.proxy) {
          const score = sa.scamalytics_score;
          const risk = sa.scamalytics_risk;
          let riskText = "Unknown";
          let badgeClass = "badge-neutral";
          if (risk && score !== undefined) {
              riskText = \`\${score} - \${risk.charAt(0).toUpperCase() + risk.slice(1)}\`;
              switch (risk.toLowerCase()) {
                  case "low": badgeClass = "badge-yes"; break;
                  case "medium": badgeClass = "badge-warning"; break;
                  case "high": case "very high": badgeClass = "badge-no"; break;
              }
          }
          elements.proxy.innerHTML = \`<span class="badge \${badgeClass}">\${riskText}</span>\`;
        }
      }

      function updateIpApiIoDisplay(geo, prefix, originalHost) {
        const hostElement = document.getElementById(\`\${prefix}-host\`);
        if (hostElement) hostElement.textContent = originalHost || "N/A";
        const elements = {
          ip: document.getElementById(\`\${prefix}-ip\`), location: document.getElementById(\`\${prefix}-location\`),
          isp: document.getElementById(\`\${prefix}-isp\`)
        };
        if (!geo || geo.error) {
          const errorMessage = geo ? geo.reason : 'N/A';
          Object.values(elements).forEach(el => { if(el) el.innerHTML = errorMessage; });
          if (elements.ip) elements.ip.innerHTML = "N/A";
          return;
        }
        if (elements.ip) elements.ip.textContent = geo.ip || "N/A";
        if (elements.location) {
          const city = geo.city || '';
          const countryName = geo.country_name || '';
          const countryCode = geo.country_code ? geo.country_code.toLowerCase() : '';
          let flagElementHtml = countryCode ? \`<img src="https://flagcdn.com/w20/\${countryCode}.png" srcset="https://flagcdn.com/w40/\${countryCode}.png 2x" alt="\${geo.country_code}" class="country-flag"> \` : '';
          let textPart = [city, countryName].filter(Boolean).join(', ');
          elements.location.innerHTML = (flagElementHtml || textPart) ? \`\${flagElementHtml}\${textPart}\`.trim() : "N/A";
        }
        if (elements.isp) elements.isp.textContent = geo.isp || geo.organization || geo.org || 'N/A';
      }


      async function fetchIpApiIoInfo(ip) {
        try {
          const response = await fetch(\`https://ipapi.co/\${ip}/json/\`);
          if (!response.ok) throw new Error(\`HTTP error! status: \${response.status}\`);
          return await response.json();
        } catch (error) {
          console.error('IP API Error (ipapi.co):', error);
          return null;
        }
      }

      function showError(prefix, message = "Could not load data", originalHostForProxy = null) {
        const errorMessage = "N/A";
        const elements = (prefix === 'proxy')
          ? ['host', 'ip', 'location', 'isp']
          : ['ip', 'location', 'isp', 'proxy'];

        elements.forEach(key => {
          const el = document.getElementById(\`\${prefix}-\${key}\`);
          if (!el) return;
          if (key === 'host' && prefix === 'proxy') el.textContent = originalHostForProxy || errorMessage;
          else if (key === 'proxy' && prefix === 'client') el.innerHTML = \`<span class="badge badge-neutral">N/A</span>\`;
          else el.innerHTML = errorMessage;
        });
        console.warn(\`\${prefix} data loading failed: \${message}\`);
      }

      async function loadNetworkInfo() {
        try {
          const proxyIpWithPort = document.body.getAttribute('data-proxy-ip') || "N/A";
          const proxyDomainOrIp = proxyIpWithPort.split(':')[0];
          const proxyHostEl = document.getElementById('proxy-host');
          if(proxyHostEl) proxyHostEl.textContent = proxyIpWithPort;

          if (proxyDomainOrIp && proxyDomainOrIp !== "N/A") {
            let resolvedProxyIp = proxyDomainOrIp;
            if (!/^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(proxyDomainOrIp)) {
              try {
                const dnsRes = await fetch(\`https://dns.google/resolve?name=\${encodeURIComponent(proxyDomainOrIp)}&type=A\`);
                if (dnsRes.ok) {
                    const dnsData = await dnsRes.json();
                    const ipAnswer = dnsData.Answer?.find(a => a.type === 1);
                    if (ipAnswer) resolvedProxyIp = ipAnswer.data;
                }
              } catch (e) { console.error('DNS resolution for proxy failed:', e); }
            }
            const proxyGeoData = await fetchIpApiIoInfo(resolvedProxyIp);
            updateIpApiIoDisplay(proxyGeoData, 'proxy', proxyIpWithPort);
          } else {
            showError('proxy', 'Proxy Host not available', proxyIpWithPort);
          }

          const clientIp = await fetchClientPublicIP();
          if (clientIp) {
            const clientIpElement = document.getElementById('client-ip');
            if(clientIpElement) clientIpElement.textContent = clientIp;
            const scamalyticsData = await fetchScamalyticsClientInfo(clientIp);
            updateScamalyticsClientDisplay(scamalyticsData);
          } else {
            showError('client', 'Could not determine your IP address.');
          }
        } catch (error) {
          console.error('Overall network info loading failed:', error);
          showError('proxy', \`Error: \${error.message}\`, document.body.getAttribute('data-proxy-ip') || "N/A");
          showError('client', \`Error: \${error.message}\`);
        }
      }

      document.getElementById('refresh-ip-info')?.addEventListener('click', function() {
        const button = this;
        const icon = button.querySelector('.refresh-icon');
        button.disabled = true;
        if (icon) icon.style.animation = 'spin 1s linear infinite';

        const resetToSkeleton = (prefix) => {
          const elementsToReset = ['ip', 'location', 'isp'];
          if (prefix === 'proxy') elementsToReset.push('host');
          if (prefix === 'client') elementsToReset.push('proxy');
          elementsToReset.forEach(key => {
            const element = document.getElementById(\`\${prefix}-\${key}\`);
            if (element) element.innerHTML = \`<span class="skeleton" style="width: 120px;"></span>\`;
          });
        };

        resetToSkeleton('proxy');
        resetToSkeleton('client');
        loadNetworkInfo().finally(() => setTimeout(() => {
          button.disabled = false; if (icon) icon.style.animation = '';
        }, 1000));
      });

      const style = document.createElement('style');
      style.textContent = \`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }\`;
      document.head.appendChild(style);

      document.addEventListener('DOMContentLoaded', () => {
        loadNetworkInfo();

        const hiddifyBtn = document.getElementById('hiddify-import-btn');
        const modal = document.getElementById('hiddify-dns-modal');
        const continueBtn = document.getElementById('hiddify-modal-continue');

        if (hiddifyBtn && modal && continueBtn) {
          hiddifyBtn.addEventListener('click', function(event) {
            event.preventDefault();
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('visible'), 10);
          });

          continueBtn.addEventListener('click', function() {
            modal.classList.remove('visible');
            setTimeout(() => {
                modal.style.display = 'none';
                window.location.href = hiddifyBtn.href;
            }, 300);
          });

          modal.addEventListener('click', function(event) {
            if (event.target === modal) {
              modal.classList.remove('visible');
              setTimeout(() => modal.style.display = 'none', 300);
            }
          });;
        }
      });
  `;
}

/* ---------------------- Admin Panel & Helpers ---------------------- */

async function handleAdminLogin(request, env, cfg) {
  const url = new URL(request.url);
  if (request.method === "POST") {
    const form = await request.formData();
    const password = String(form.get("password") || "");
    // For compatibility with previous scripts: use UUID as admin secret
    if (password === String(cfg.userID)) {
      const headers = new Headers({ Location: "/admin/panel" });
      headers.append("Set-Cookie", `cf_admin=1; Path=/; HttpOnly`);
      return new Response(null, { status: 302, headers });
    }
    return new Response(adminLoginHTML({ error: "Invalid credentials" }), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  return new Response(adminLoginHTML({}), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function isAdminRequest(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.includes("cf_admin=1");
}

async function handleAdminPanel(request, env, cfg) {
  if (!isAdminRequest(request)) {
    return new Response(null, { status: 302, headers: { Location: "/admin" } });
  }
  return new Response(adminPanelHTML(cfg), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleAdminApi(request, env, cfg) {
  if (!isAdminRequest(request)) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  const url = new URL(request.url);
  const path = url.pathname.replace("/admin/api/", "");
  // Basic D1-backed user storage: requires a D1 binding named DB
  const db = env.DB;

  if (!db) return new Response(JSON.stringify({ error: "D1 binding DB not configured" }), { status: 501, headers: { "Content-Type": "application/json" } });

  if (path === "users" && request.method === "GET") {
    try {
      const res = await db.prepare("SELECT id, name, uuid, created_at FROM users ORDER BY created_at DESC").all();
      return new Response(JSON.stringify(res.results || []), { headers: { "Content-Type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.toString() }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  if (path === "users" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    const name = body.name || "new";
    const uuid = body.uuid || cfg.userID;
    try {
      await db.prepare("INSERT INTO users (name, uuid, created_at) VALUES (?, ?, strftime('%s','now'))").run(name, uuid);
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.toString() }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  if (path === "health" && request.method === "POST") {
    try {
      const result = await performHealthCheck(env);
      return new Response(JSON.stringify({ ok: true, result }), { headers: { "Content-Type": "application/json" } });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.toString() }), { status: 500, headers: { "Content-Type": "application/json" } });
    }
  }

  return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: { "Content-Type": "application/json" } });
}

function adminLoginHTML({ error } = {}) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title><style>body{font-family:system-ui,Arial;padding:24px;background:#121212;color:#eee}form{max-width:420px;margin:40px auto;padding:18px;border-radius:8px;background:#1e1e1e;border:1px solid #2c2c2c}label{display:block;margin-bottom:8px}input{width:100%;padding:8px;margin-bottom:12px;border-radius:6px;border:1px solid #333;background:#0f0f0f;color:#fff}button{padding:10px 14px;border-radius:6px;background:#3a6; color:#071}</style></head><body><form method="POST"><h2>Admin Login</h2>${error ? `<p style="color:#f66">${escapeHtml(error)}</p>` : ""}<label>Password</label><input name="password" type="password" autocomplete="off" required><button type="submit">Sign in</button></form></body></html>`;
}

function adminPanelHTML(cfg) {
  // Small admin UI with embedded QR generation script (lightweight fallback)
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Panel</title><style>body{font-family:system-ui,Arial;background:#0b0b0b;color:#eee;padding:16px}header{display:flex;align-items:center;justify-content:space-between}main{max-width:980px;margin:18px auto}textarea{width:100%;height:84px;background:#0f0f0f;color:#fff;border:1px solid #222;padding:8px;border-radius:6px}button{padding:8px 12px;border-radius:6px;background:#2b8;color:#041;border:none;cursor:pointer;margin-right:8px}#qr{width:240px;height:240px;border:1px solid #222;background:#fff;padding:6px;display:inline-block}</style></head><body><header><h1>Admin Panel</h1><div><a href="/">Site</a></div></header><main><section><h2>Generate Subscription / QR</h2><p>Paste a single link (vless://...) or multiple links (one per line) and click Generate.</p><textarea id="links" placeholder="paste vless links here"></textarea><div style="margin-top:8px"><button id="gen">Generate</button><button id="copy">Copy</button><button id="download">Download</button></div><div style="margin-top:16px"><div id="qr"></div></div></section><section style="margin-top:28px"><h2>Users</h2><div id="users-root">Loading...</div></section></main><script>
  // Inlined full qrcode.min.js (qrcodejs v1.0.0) followed by a small runtime wrapper.
  // The library (QRCode) is placed into the page scope; we then use it to render into #qr.
  (function(){
    /* qrcode.min.js start */
  var QRCode;!function(){function a(a){this.mode=c.MODE_8BIT_BYTE,this.data=a,this.parsedData=[];for(var b=[],d=0,e=this.data.length;e>d;d++){var f=this.data.charCodeAt(d);f>65536?(b[0]=240|(1835008&f)>>>18,b[1]=128|(258048&f)>>>12,b[2]=128|(4032&f)>>>6,b[3]=128|63&f):f>2048?(b[0]=224|(61440&f)>>>12,b[1]=128|(4032&f)>>>6,b[2]=128|63&f):f>128?(b[0]=192|(1984&f)>>>6,b[1]=128|63&f):b[0]=f,this.parsedData=this.parsedData.concat(b)}this.parsedData.length!=this.data.length&&(this.parsedData.unshift(191),this.parsedData.unshift(187),this.parsedData.unshift(239))}function b(a,b){this.typeNumber=a,this.errorCorrectLevel=b,this.modules=null,this.moduleCount=0,this.dataCache=null,this.dataList=[]}function i(a,b){if(void 0==a.length)throw new Error(a.length+"/"+b);for(var c=0;c<a.length&&0==a[c];)c++;this.num=new Array(a.length-c+b);for(var d=0;d<a.length-c;d++)this.num[d]=a[d+c]}function j(a,b){this.totalCount=a,this.dataCount=b}function k(){this.buffer=[],this.length=0}function m(){return"undefined"!=typeof CanvasRenderingContext2D}function n(){var a=!1,b=navigator.userAgent;return/android/i.test(b)&&(a=!0,aMat=b.toString().match(/android ([0-9]\.[0-9])/i),aMat&&aMat[1]&&(a=parseFloat(aMat[1]))),a}function r(a,b){for(var c=1,e=s(a),f=0,g=l.length;g>=f;f++){var h=0;switch(b){case d.L:h=l[f][0];break;case d.M:h=l[f][1];break;case d.Q:h=l[f][2];break;case d.H:h=l[f][3]}if(h>=e)break;c++}if(c>l.length)throw new Error("Too long data");return c}function s(a){var b=encodeURI(a).toString().replace(/\%[0-9a-fA-F]{2}/g,"a");return b.length+(b.length!=a?3:0)}a.prototype={getLength:function(){return this.parsedData.length},write:function(a){for(var b=0,c=this.parsedData.length;c>b;b++)a.put(this.parsedData[b],8)}},b.prototype={addData:function(b){var c=new a(b);this.dataList.push(c),this.dataCache=null},isDark:function(a,b){if(0>a||this.moduleCount<=a||0>b||this.moduleCount<=b)throw new Error(a+","+b);return this.modules[a][b]},getModuleCount:function(){return this.moduleCount},make:function(){this.makeImpl(!1,this.getBestMaskPattern())},makeImpl:function(a,c){this.moduleCount=4*this.typeNumber+17,this.modules=new Array(this.moduleCount);for(var d=0;d<this.moduleCount;d++){this.modules[d]=new Array(this.moduleCount);for(var e=0;e<this.moduleCount;e++)this.modules[d][e]=null}this.setupPositionProbePattern(0,0),this.setupPositionProbePattern(this.moduleCount-7,0),this.setupPositionProbePattern(0,this.moduleCount-7),this.setupPositionAdjustPattern(),this.setupTimingPattern(),this.setupTypeInfo(a,c),this.typeNumber>=7&&this.setupTypeNumber(a),null==this.dataCache&&(this.dataCache=b.createData(this.typeNumber,this.errorCorrectLevel,this.dataList)),this.mapData(this.dataCache,c)},setupPositionProbePattern:function(a,b){for(var c=-1;7>=c;c++)if(!(-1>=a+c||this.moduleCount<=a+c))for(var d=-1;7>=d;d++)-1>=b+d||this.moduleCount<=b+d||(this.modules[a+c][b+d]=c>=0&&6>=c&&(0==d||6==d)||d>=0&&6>=d&&(0==c||6==c)||c>=2&&4>=c&&d>=2&&4>=d?!0:!1)},getBestMaskPattern:function(){for(var a=0,b=0,c=0;8>c;c++){this.makeImpl(!0,c);var d=f.getLostPoint(this);(0==c||a>d)&&(a=d,b=c)}return b},createMovieClip:function(a,b,c){var d=a.createEmptyMovieClip(b,c),e=1;this.make();for(var f=0;f<this.modules.length;f++)for(var g=f*e,h=0;h<this.modules[f].length;h++){var i=h*e,j=this.modules[f][h];j&&(d.beginFill(0,100),d.moveTo(i,g),d.lineTo(i+e,g),d.lineTo(i+e,g+e),d.lineTo(i,g+e),d.endFill())}return d},setupTimingPattern:function(){for(var a=8;a<this.moduleCount-8;a++)null==this.modules[a][6]&&(this.modules[a][6]=0==a%2);for(var b=8;b<this.moduleCount-8;b++)null==this.modules[6][b]&&(this.modules[6][b]=0==b%2)},setupPositionAdjustPattern:function(){for(var a=f.getPatternPosition(this.typeNumber),b=0;b<a.length;b++)for(var c=0;c<a.length;c++){var d=a[b],e=a[c];if(null==this.modules[d][e])for(var g=-2;2>=g;g++)for(var h=-2;2>=h;h++)this.modules[d+g][e+h]=-2==g||2==g||-2==h||2==h||0==g&&0==h?!0:!1}},setupTypeNumber:function(a){for(var b=f.getBCHTypeNumber(this.typeNumber),c=0;18>c;c++){var d=!a&&1==(1&b>>c);this.modules[Math.floor(c/3)][c%3+this.moduleCount-8-3]=d}for(var c=0;18>c;c++){var d=!a&&1==(1&b>>c);this.modules[c%3+this.moduleCount-8-3][Math.floor(c/3)]=d}},setupTypeInfo:function(a,b){for(var c=this.errorCorrectLevel<<3|b,d=f.getBCHTypeInfo(c),e=0;15>e;e++){var g=!a&&1==(1&d>>e);6>e?this.modules[e][8]=g:8>e?this.modules[e+1][8]=g:this.modules[this.moduleCount-15+e][8]=g}for(var e=0;15>e;e++){var g=!a&&1==(1&d>>e);8>e?this.modules[8][this.moduleCount-e-1]=g:9>e?this.modules[8][15-e-1+1]=g:this.modules[8][15-e-1]=g}this.modules[this.moduleCount-8][8]=!a},mapData:function(a,b){for(var c=-1,d=this.moduleCount-1,e=7,g=0,h=this.moduleCount-1;h>0;h-=2)for(6==h&&h--;;){for(var i=0;2>i;i++)if(null==this.modules[d][h-i]){var j=!1;g<a.length&&(j=1==(1&a[g]>>>e));var k=f.getMask(b,d,h-i);k&&(j=!j),this.modules[d][h-i]=j,e--,-1==e&&(g++,e=7)}if(d+=c,0>d||this.moduleCount<=d){d-=c,c=-c;break}}}},b.PAD0=236,b.PAD1=17,b.createData=function(a,c,d){for(var e=j.getRSBlocks(a,c),g=new k,h=0;h<d.length;h++){var i=d[h];g.put(i.mode,4),g.put(i.getLength(),f.getLengthInBits(i.mode,a)),i.write(g)}for(var l=0,h=0;h<e.length;h++)l+=e[h].dataCount;if(g.getLengthInBits()>8*l)throw new Error("code length overflow. ("+g.getLengthInBits()+">"+8*l+")");for(g.getLengthInBits()+4<=8*l&&g.put(0,4);0!=g.getLengthInBits()%8;)g.putBit(!1);for(;;){if(g.getLengthInBits()>=8*l)break;if(g.put(b.PAD0,8),g.getLengthInBits()>=8*l)break;g.put(b.PAD1,8)}return b.createBytes(g,e)},b.createBytes=function(a,b){for(var c=0,d=0,e=0,g=new Array(b.length),h=new Array(b.length),j=0;j<b.length;j++){var k=b[j].dataCount,l=b[j].totalCount-k;d=Math.max(d,k),e=Math.max(e,l),g[j]=new Array(k);for(var m=0;m<g[j].length;m++)g[j][m]=255&a.buffer[m+c];c+=k;var n=f.getErrorCorrectPolynomial(l),o=new i(g[j],n.getLength()-1),p=o.mod(n);h[j]=new Array(n.getLength()-1);for(var m=0;m<h[j].length;m++){var q=m+p.getLength()-h[j].length;h[j][m]=q>=0?p.get(q):0}}for(var r=0,m=0;m<b.length;m++)r+=b[m].totalCount;for(var s=new Array(r),t=0,m=0;d>m;m++)for(var j=0;j<b.length;j++)m<g[j].length&&(s[t++]=g[j][m]);for(var m=0;e>m;m++)for(var j=0;j<b.length;j++)m<h[j].length&&(s[t++]=h[j][m]);return s};for(var c={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8},d={L:1,M:0,Q:3,H:2},e={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7},f={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:1335,G18:7973,G15_MASK:21522,getBCHTypeInfo:function(a){for(var b=a<<10;f.getBCHDigit(b)-f.getBCHDigit(f.G15)>=0;)b^=f.G15<<f.getBCHDigit(b)-f.getBCHDigit(f.G15);return(a<<10|b)^f.G15_MASK},getBCHTypeNumber:function(a){for(var b=a<<12;f.getBCHDigit(b)-f.getBCHDigit(f.G18)>=0;)b^=f.G18<<f.getBCHDigit(b)-f.getBCHDigit(f.G18);return a<<12|b},getBCHDigit:function(a){for(var b=0;0!=a;)b++,a>>>=1;return b},getPatternPosition:function(a){return f.PATTERN_POSITION_TABLE[a-1]},getMask:function(a,b,c){switch(a){case e.PATTERN000:return 0==(b+c)%2;case e.PATTERN001:return 0==b%2;case e.PATTERN010:return 0==c%3;case e.PATTERN011:return 0==(b+c)%3;case e.PATTERN100:return 0==(Math.floor(b/2)+Math.floor(c/3))%2;case e.PATTERN101:return 0==b*c%2+b*c%3;case e.PATTERN110:return 0==(b*c%2+b*c%3)%2;case e.PATTERN111:return 0==(b*c%3+(b+c)%2)%2;default:throw new Error("bad maskPattern:"+a)}},getErrorCorrectPolynomial:function(a){for(var b=new i([1],0),c=0;a>c;c++)b=b.multiply(new i([1,g.gexp(c)],0));return b},getLengthInBits:function(a,b){if(b>=1&&10>b)switch(a){case c.MODE_NUMBER:return 10;case c.MODE_ALPHA_NUM:return 9;case c.MODE_8BIT_BYTE:return 8;case c.MODE_KANJI:return 8;default:throw new Error("mode:"+a)}else if(27>b)switch(a){case c.MODE_NUMBER:return 12;case c.MODE_ALPHA_NUM:return 11;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 10;default:throw new Error("mode:"+a)}else{if(!(41>b))throw new Error("type:"+b);switch(a){case c.MODE_NUMBER:return 14;case c.MODE_ALPHA_NUM:return 13;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 12;default:throw new Error("mode:"+a)}}},getLostPoint:function(a){for(var b=a.getModuleCount(),c=0,d=0;b>d;d++)for(var e=0;b>e;e++){for(var f=0,g=a.isDark(d,e),h=-1;1>=h;h++)if(!(0>d+h||d+h>=b))for(var i=-1;1>=i;i++)0>e+i||e+i>=b||(0!=h||0!=i)&&g==a.isDark(d+h,e+i)&&f++;f>5&&(c+=3+f-5)}for(var d=0;b-1>d;d++)for(var e=0;b-1>e;e++){var j=0;a.isDark(d,e)&&j++,a.isDark(d+1,e)&&j++,a.isDark(d,e+1)&&j++,a.isDark(d+1,e+1)&&j++,(0==j||4==j)&&(c+=3)}for(var d=0;b>d;d++)for(var e=0;b-6>e;e++)a.isDark(d,e)&&!a.isDark(d,e+1)&&a.isDark(d,e+2)&&a.isDark(d,e+3)&&a.isDark(d,e+4)&&!a.isDark(d,e+5)&&a.isDark(d,e+6)&&(c+=40);for(var e=0;b>e;e++)for(var d=0;b-6>d;d++)a.isDark(d,e)&&!a.isDark(d+1,e)&&a.isDark(d+2,e)&&a.isDark(d+3,e)&&a.isDark(d+4,e)&&!a.isDark(d+5,e)&&a.isDark(d+6,e)&&(c+=40);for(var k=0,e=0;b>e;e++)for(var d=0;b>d;d++)a.isDark(d,e)&&k++;var l=Math.abs(100*k/b/b-50)/5;return c+=10*l}},g={glog:function(a){if(1>a)throw new Error("glog("+a+")");return g.LOG_TABLE[a]},gexp:function(a){for(;0>a;)a+=255;for(;a>=256;)a-=255;return g.EXP_TABLE[a]},EXP_TABLE:new Array(256),LOG_TABLE:new Array(256)},h=0;8>h;h++)g.EXP_TABLE[h]=1<<h;for(var h=8;256>h;h++)g.EXP_TABLE[h]=g.EXP_TABLE[h-4]^g.EXP_TABLE[h-5]^g.EXP_TABLE[h-6]^g.EXP_TABLE[h-8];for(var h=0;255>h;h++)g.LOG_TABLE[g.EXP_TABLE[h]]=h;i.prototype={get:function(a){return this.num[a]},getLength:function(){return this.num.length},multiply:function(a){for(var b=new Array(this.getLength()+a.getLength()-1),c=0;c<this.getLength();c++)for(var d=0;d<a.getLength();d++)b[c+d]^=g.gexp(g.glog(this.get(c))+g.glog(a.get(d)));return new i(b,0)},mod:function(a){if(this.getLength()-a.getLength()<0)return this;for(var b=g.glog(this.get(0))-g.glog(a.get(0)),c=new Array(this.getLength()),d=0;d<this.getLength();d++)c[d]=this.get(d);for(var d=0;d<a.getLength();d++)c[d]^=g.gexp(g.glog(a.get(d))+b);return new i(c,0).mod(a)}},j.RS_BLOCK_TABLE=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25]],j.getRSBlocks=function(a,b){var c=j.getRsBlockTable(a,b);if(void 0==c)throw new Error("bad rs block @ typeNumber:"+a+"/errorCorrectLevel:"+b);for(var d=c.length/3,e=[],f=0;d>f;f++)for(var g=c[3*f+0],h=c[3*f+1],i=c[3*f+2],k=0;g>k;k++)e.push(new j(h,i));return e},j.getRsBlockTable=function(a,b){switch(b){case d.L:return j.RS_BLOCK_TABLE[4*(a-1)+0];case d.M:return j.RS_BLOCK_TABLE[4*(a-1)+1];case d.Q:return j.RS_BLOCK_TABLE[4*(a-1)+2];case d.H:return j.RS_BLOCK_TABLE[4*(a-1)+3];default:return void 0}};QRCode=function(a,b){if(this._htOption={width:256,height:256,typeNumber:4,colorDark:"#000000",colorLight:"#ffffff",correctLevel:d.H},"string"==typeof b&&(b={text:b}),b)for(var c in b)this._htOption[c]=b[c];"string"==typeof a&&(a=document.getElementById(a)),this._android=n(),this._el=a,this._oQRCode=null,this._oDrawing=new q(this._el,this._htOption),this._htOption.text&&this.makeCode(this._htOption.text)},QRCode.prototype.makeCode=function(a){this._oQRCode=new b(r(a,this._htOption.correctLevel),this._htOption.correctLevel),this._oQRCode.addData(a),this._oQRCode.make(),this._el.title=a,this._oDrawing.draw(this._oQRCode),this.makeImage()},QRCode.prototype.makeImage=function(){"function"==typeof this._oDrawing.makeImage&&(!this._android||this._android>=3)&&this._oDrawing.makeImage()},QRCode.prototype.clear=function(){this._oDrawing.clear()},QRCode.CorrectLevel=d}();
/* qrcode.min.js end */
(function(){document.addEventListener('DOMContentLoaded', function(){function renderWithQRCodeLib(txt){const container=document.getElementById('qr');container.innerHTML='';try{new QRCode(container,{text:txt,width:240,height:240,colorDark:'#000000',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.H});}catch(e){container.textContent='QR generation failed';}};document.getElementById('gen').addEventListener('click',function(){const txt=document.getElementById('links').value.trim();if(!txt)return alert('Paste a link first');renderWithQRCodeLib(txt);});document.getElementById('copy').addEventListener('click',async function(){const val=document.getElementById('links').value;if(!val)return;try{await navigator.clipboard.writeText(val);alert('Copied');}catch(e){alert('Copy failed');}});document.getElementById('download').addEventListener('click',function(){const val=document.getElementById('links').value;if(!val)return;const blob=new Blob([val],{type:'text/plain'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='subscription.txt';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);});});})();</script></body></html>`;
}

function escapeHtml(s){ return String(s).replace(/[&<>\"']/g, function(c){ return {'&':'&amp;','<': '&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }

async function handleUserPanel(request, env, cfg) {
  // Public user panel: shows subscription links and QR generator for the visitor
  const html = userPanelHTML(cfg, (new URL(request.url)).hostname);
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function userPanelHTML(cfg, host) {
  const subXrayUrl = `https://${host}/xray/${cfg.userID}`;
  const subSbUrl = `https://${host}/sb/${cfg.userID}`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>User Panel</title><style>body{font-family:system-ui,Arial;background:#0b0b0b;color:#eee;padding:16px}main{max-width:900px;margin:18px auto}textarea{width:100%;height:84px;background:#0f0f0f;color:#fff;border:1px solid #222;padding:8px;border-radius:6px}button{padding:8px 12px;border-radius:6px;background:#2b8;color:#041;border:none;cursor:pointer;margin-right:8px}#qr{width:240px;height:240px;border:1px solid #222;background:#fff;padding:6px;display:inline-block}</style></head><body><main><h1>Your Subscriptions</h1><p>Subscription (Xray): <a href="${subXrayUrl}">${subXrayUrl}</a></p><p>Subscription (Singbox): <a href="${subSbUrl}">${subSbUrl}</a></p><section style="margin-top:18px"><h2>Generate QR</h2><textarea id="links" placeholder="Paste vless link here">${escapeHtml(subXrayUrl)}</textarea><div style="margin-top:8px"><button id="gen">Generate</button><button id="copy">Copy</button><button id="download">Download</button></div><div style="margin-top:16px"><div id="qr"></div></div></section></main><script>/* qrcode.min.js start */
var QRCode;!function(){function a(a){this.mode=c.MODE_8BIT_BYTE,this.data=a,this.parsedData=[];for(var b=[],d=0,e=this.data.length;e>d;d++){var f=this.data.charCodeAt(d);f>65536?(b[0]=240|(1835008&f)>>>18,b[1]=128|(258048&f)>>>12,b[2]=128|(4032&f)>>>6,b[3]=128|63&f):f>2048?(b[0]=224|(61440&f)>>>12,b[1]=128|(4032&f)>>>6,b[2]=128|63&f):f>128?(b[0]=192|(1984&f)>>>6,b[1]=128|63&f):b[0]=f,this.parsedData=this.parsedData.concat(b)}this.parsedData.length!=this.data.length&&(this.parsedData.unshift(191),this.parsedData.unshift(187),this.parsedData.unshift(239))}function b(a,b){this.typeNumber=a,this.errorCorrectLevel=b,this.modules=null,this.moduleCount=0,this.dataCache=null,this.dataList=[]}function i(a,b){if(void 0==a.length)throw new Error(a.length+"/"+b);for(var c=0;c<a.length&&0==a[c];)c++;this.num=new Array(a.length-c+b);for(var d=0;d<a.length-c;d++)this.num[d]=a[d+c]}function j(a,b){this.totalCount=a,this.dataCount=b}function k(){this.buffer=[],this.length=0}function m(){return"undefined"!=typeof CanvasRenderingContext2D}function n(){var a=!1,b=navigator.userAgent;return/android/i.test(b)&&(a=!0,aMat=b.toString().match(/android ([0-9]\.[0-9])/i),aMat&&aMat[1]&&(a=parseFloat(aMat[1]))),a}function r(a,b){for(var c=1,e=s(a),f=0,g=l.length;g>=f;f++){var h=0;switch(b){case d.L:h=l[f][0];break;case d.M:h=l[f][1];break;case d.Q:h=l[f][2];break;case d.H:h=l[f][3]}if(h>=e)break;c++}if(c>l.length)throw new Error("Too long data");return c}function s(a){var b=encodeURI(a).toString().replace(/\%[0-9a-fA-F]{2}/g,"a");return b.length+(b.length!=a?3:0)}a.prototype={getLength:function(){return this.parsedData.length},write:function(a){for(var b=0,c=this.parsedData.length;c>b;b++)a.put(this.parsedData[b],8)}},b.prototype={addData:function(b){var c=new a(b);this.dataList.push(c),this.dataCache=null},isDark:function(a,b){if(0>a||this.moduleCount<=a||0>b||this.moduleCount<=b)throw new Error(a+","+b);return this.modules[a][b]},getModuleCount:function(){return this.moduleCount},make:function(){this.makeImpl(!1,this.getBestMaskPattern())},makeImpl:function(a,c){this.moduleCount=4*this.typeNumber+17,this.modules=new Array(this.moduleCount);for(var d=0;d<this.moduleCount;d++){this.modules[d]=new Array(this.moduleCount);for(var e=0;e<this.moduleCount;e++)this.modules[d][e]=null}this.setupPositionProbePattern(0,0),this.setupPositionProbePattern(this.moduleCount-7,0),this.setupPositionProbePattern(0,this.moduleCount-7),this.setupPositionAdjustPattern(),this.setupTimingPattern(),this.setupTypeInfo(a,c),this.typeNumber>=7&&this.setupTypeNumber(a),null==this.dataCache&&(this.dataCache=b.createData(this.typeNumber,this.errorCorrectLevel,this.dataList)),this.mapData(this.dataCache,c)},setupPositionProbePattern:function(a,b){for(var c=-1;7>=c;c++)if(!(-1>=a+c||this.moduleCount<=a+c))for(var d=-1;7>=d;d++)-1>=b+d||this.moduleCount<=b+d||(this.modules[a+c][b+d]=c>=0&&6>=c&&(0==d||6==d)||d>=0&&6>=d&&(0==c||6==c)||c>=2&&4>=c&&d>=2&&4>=d?!0:!1)},getBestMaskPattern:function(){for(var a=0,b=0,c=0;8>c;c++){this.makeImpl(!0,c);var d=f.getLostPoint(this);(0==c||a>d)&&(a=d,b=c)}return b},createMovieClip:function(a,b,c){var d=a.createEmptyMovieClip(b,c),e=1;this.make();for(var f=0;f<this.modules.length;f++)for(var g=f*e,h=0;h<this.modules[f].length;h++){var i=h*e,j=this.modules[f][h];j&&(d.beginFill(0,100),d.moveTo(i,g),d.lineTo(i+e,g),d.lineTo(i+e,g+e),d.lineTo(i,g+e),d.endFill())}return d},setupTimingPattern:function(){for(var a=8;a<this.moduleCount-8;a++)null==this.modules[a][6]&&(this.modules[a][6]=0==a%2);for(var b=8;b<this.moduleCount-8;b++)null==this.modules[6][b]&&(this.modules[6][b]=0==b%2)},setupPositionAdjustPattern:function(){for(var a=f.getPatternPosition(this.typeNumber),b=0;b<a.length;b++)for(var c=0;c<a.length;c++){var d=a[b],e=a[c];if(null==this.modules[d][e])for(var g=-2;2>=g;g++)for(var h=-2;2>=h;h++)this.modules[d+g][e+h]=-2==g||2==g||-2==h||2==h||0==g&&0==h?!0:!1}},setupTypeNumber:function(a){for(var b=f.getBCHTypeNumber(this.typeNumber),c=0;18>c;c++){var d=!a&&1==(1&b>>c);this.modules[Math.floor(c/3)][c%3+this.moduleCount-8-3]=d}for(var c=0;18>c;c++){var d=!a&&1==(1&b>>c);this.modules[c%3+this.moduleCount-8-3][Math.floor(c/3)]=d}},setupTypeInfo:function(a,b){for(var c=this.errorCorrectLevel<<3|b,d=f.getBCHTypeInfo(c),e=0;15>e;e++){var g=!a&&1==(1&d>>e);6>e?this.modules[e][8]=g:8>e?this.modules[e+1][8]=g:this.modules[this.moduleCount-15+e][8]=g}for(var e=0;15>e;e++){var g=!a&&1==(1&d>>e);8>e?this.modules[8][this.moduleCount-e-1]=g:9>e?this.modules[8][15-e-1+1]=g:this.modules[8][15-e-1]=g}this.modules[this.moduleCount-8][8]=!a},mapData:function(a,b){for(var c=-1,d=this.moduleCount-1,e=7,g=0,h=this.moduleCount-1;h>0;h-=2)for(6==h&&h--;;){for(var i=0;2>i;i++)if(null==this.modules[d][h-i]){var j=!1;g<a.length&&(j=1==(1&a[g]>>>e));var k=f.getMask(b,d,h-i);k&&(j=!j),this.modules[d][h-i]=j,e--,-1==e&&(g++,e=7)}if(d+=c,0>d||this.moduleCount<=d){d-=c,c=-c;break}}}},b.PAD0=236,b.PAD1=17,b.createData=function(a,c,d){for(var e=j.getRSBlocks(a,c),g=new k,h=0;h<d.length;h++){var i=d[h];g.put(i.mode,4),g.put(i.getLength(),f.getLengthInBits(i.mode,a)),i.write(g)}for(var l=0,h=0;h<e.length;h++)l+=e[h].dataCount;if(g.getLengthInBits()>8*l)throw new Error("code length overflow. ("+g.getLengthInBits()+">"+8*l+")");for(g.getLengthInBits()+4<=8*l&&g.put(0,4);0!=g.getLengthInBits()%8;)g.putBit(!1);for(;;){if(g.getLengthInBits()>=8*l)break;if(g.put(b.PAD0,8),g.getLengthInBits()>=8*l)break;g.put(b.PAD1,8)}return b.createBytes(g,e)},b.createBytes=function(a,b){for(var c=0,d=0,e=0,g=new Array(b.length),h=new Array(b.length),j=0;j<b.length;j++){var k=b[j].dataCount,l=b[j].totalCount-k;d=Math.max(d,k),e=Math.max(e,l),g[j]=new Array(k);for(var m=0;m<g[j].length;m++)g[j][m]=255&a.buffer[m+c];c+=k;var n=f.getErrorCorrectPolynomial(l),o=new i(g[j],n.getLength()-1),p=o.mod(n);h[j]=new Array(n.getLength()-1);for(var m=0;m<h[j].length;m++){var q=m+p.getLength()-h[j].length;h[j][m]=q>=0?p.get(q):0}}for(var r=0,m=0;m<b.length;m++)r+=b[m].totalCount;for(var s=new Array(r),t=0,m=0;d>m;m++)for(var j=0;j<b.length;j++)m<g[j].length&&(s[t++]=g[j][m]);for(var m=0;e>m;m++)for(var j=0;j<b.length;j++)m<h[j].length&&(s[t++]=h[j][m]);return s};for(var c={MODE_NUMBER:1,MODE_ALPHA_NUM:2,MODE_8BIT_BYTE:4,MODE_KANJI:8},d={L:1,M:0,Q:3,H:2},e={PATTERN000:0,PATTERN001:1,PATTERN010:2,PATTERN011:3,PATTERN100:4,PATTERN101:5,PATTERN110:6,PATTERN111:7},f={PATTERN_POSITION_TABLE:[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50],[6,30,54],[6,32,58],[6,34,62],[6,26,46,66],[6,26,48,70],[6,26,50,74],[6,30,54,78],[6,30,56,82],[6,30,58,86],[6,34,62,90],[6,28,50,72,94],[6,26,50,74,98],[6,30,54,78,102],[6,28,54,80,106],[6,32,58,84,110],[6,30,58,86,114],[6,34,62,90,118],[6,26,50,74,98,122],[6,30,54,78,102,126],[6,26,52,78,104,130],[6,30,56,82,108,134],[6,34,60,86,112,138],[6,30,58,86,114,142],[6,34,62,90,118,146],[6,30,54,78,102,126,150],[6,24,50,76,102,128,154],[6,28,54,80,106,132,158],[6,32,58,84,110,136,162],[6,26,54,82,110,138,166],[6,30,58,86,114,142,170]],G15:1335,G18:7973,G15_MASK:21522,getBCHTypeInfo:function(a){for(var b=a<<10;f.getBCHDigit(b)-f.getBCHDigit(f.G15)>=0;)b^=f.G15<<f.getBCHDigit(b)-f.getBCHDigit(f.G15);return(a<<10|b)^f.G15_MASK},getBCHTypeNumber:function(a){for(var b=a<<12;f.getBCHDigit(b)-f.getBCHDigit(f.G18)>=0;)b^=f.G18<<f.getBCHDigit(b)-f.getBCHDigit(f.G18);return a<<12|b},getBCHDigit:function(a){for(var b=0;0!=a;)b++,a>>>=1;return b},getPatternPosition:function(a){return f.PATTERN_POSITION_TABLE[a-1]},getMask:function(a,b,c){switch(a){case e.PATTERN000:return 0==(b+c)%2;case e.PATTERN001:return 0==b%2;case e.PATTERN010:return 0==c%3;case e.PATTERN011:return 0==(b+c)%3;case e.PATTERN100:return 0==(Math.floor(b/2)+Math.floor(c/3))%2;case e.PATTERN101:return 0==b*c%2+b*c%3;case e.PATTERN110:return 0==(b*c%2+b*c%3)%2;case e.PATTERN111:return 0==(b*c%3+(b+c)%2)%2;default:throw new Error("bad maskPattern:"+a)}},getErrorCorrectPolynomial:function(a){for(var b=new i([1],0),c=0;a>c;c++)b=b.multiply(new i([1,g.gexp(c)],0));return b},getLengthInBits:function(a,b){if(b>=1&&10>b)switch(a){case c.MODE_NUMBER:return 10;case c.MODE_ALPHA_NUM:return 9;case c.MODE_8BIT_BYTE:return 8;case c.MODE_KANJI:return 8;default:throw new Error("mode:"+a)}else if(27>b)switch(a){case c.MODE_NUMBER:return 12;case c.MODE_ALPHA_NUM:return 11;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 10;default:throw new Error("mode:"+a)}else{if(!(41>b))throw new Error("type:"+b);switch(a){case c.MODE_NUMBER:return 14;case c.MODE_ALPHA_NUM:return 13;case c.MODE_8BIT_BYTE:return 16;case c.MODE_KANJI:return 12;default:throw new Error("mode:"+a)}}},getLostPoint:function(a){for(var b=a.getModuleCount(),c=0,d=0;b>d;d++)for(var e=0;b>e;e++){for(var f=0,g=a.isDark(d,e),h=-1;1>=h;h++)if(!(0>d+h||d+h>=b))for(var i=-1;1>=i;i++)0>e+i||e+i>=b||(0!=h||0!=i)&&g==a.isDark(d+h,e+i)&&f++;f>5&&(c+=3+f-5)}for(var d=0;b-1>d;d++)for(var e=0;b-1>e;e++){var j=0;a.isDark(d,e)&&j++,a.isDark(d+1,e)&&j++,a.isDark(d,e+1)&&j++,a.isDark(d+1,e+1)&&j++,(0==j||4==j)&&(c+=3)}for(var d=0;b>d;d++)for(var e=0;b-6>e;e++)a.isDark(d,e)&&!a.isDark(d,e+1)&&a.isDark(d,e+2)&&a.isDark(d,e+3)&&a.isDark(d,e+4)&&!a.isDark(d,e+5)&&a.isDark(d,e+6)&&(c+=40);for(var e=0;b>e;e++)for(var d=0;b-6>d;d++)a.isDark(d,e)&&!a.isDark(d+1,e)&&a.isDark(d+2,e)&&a.isDark(d+3,e)&&a.isDark(d+4,e)&&!a.isDark(d+5,e)&&a.isDark(d+6,e)&&(c+=40);for(var k=0,e=0;b>e;e++)for(var d=0;b>d;d++)a.isDark(d,e)&&k++;var l=Math.abs(100*k/b/b-50)/5;return c+=10*l}},g={glog:function(a){if(1>a)throw new Error("glog("+a+")");return g.LOG_TABLE[a]},gexp:function(a){for(;0>a;)a+=255;for(;a>=256;)a-=255;return g.EXP_TABLE[a]},EXP_TABLE:new Array(256),LOG_TABLE:new Array(256)},h=0;8>h;h++)g.EXP_TABLE[h]=1<<h;for(var h=8;256>h;h++)g.EXP_TABLE[h]=g.EXP_TABLE[h-4]^g.EXP_TABLE[h-5]^g.EXP_TABLE[h-6]^g.EXP_TABLE[h-8];for(var h=0;255>h;h++)g.LOG_TABLE[g.EXP_TABLE[h]]=h;i.prototype={get:function(a){return this.num[a]},getLength:function(){return this.num.length},multiply:function(a){for(var b=new Array(this.getLength()+a.getLength()-1),c=0;c<this.getLength();c++)for(var d=0;d<a.getLength();d++)b[c+d]^=g.gexp(g.glog(this.get(c))+g.glog(a.get(d)));return new i(b,0)},mod:function(a){if(this.getLength()-a.getLength()<0)return this;for(var b=g.glog(this.get(0))-g.glog(a.get(0)),c=new Array(this.getLength()),d=0;d<this.getLength();d++)c[d]=this.get(d);for(var d=0;d<a.getLength();d++)c[d]^=g.gexp(g.glog(a.get(d))+b);return new i(c,0).mod(a)}},j.RS_BLOCK_TABLE=[[1,26,19],[1,26,16],[1,26,13],[1,26,9],[1,44,34],[1,44,28],[1,44,22],[1,44,16],[1,70,55],[1,70,44],[2,35,17],[2,35,13],[1,100,80],[2,50,32],[2,50,24],[4,25,9],[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],[2,86,68],[4,43,27],[4,43,19],[4,43,15],[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],[4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],[2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],[4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],[3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],[5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12],[5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],[1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],[5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],[3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],[3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],[4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],[2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],[4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],[6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],[8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],[10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],[8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],[3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],[7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],[5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],[13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],[17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],[17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],[13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],[12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],[6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],[17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],[4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],[20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16],[19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25]],j.getRSBlocks=function(a,b){var c=j.getRsBlockTable(a,b);if(void 0==c)throw new Error("bad rs block @ typeNumber:"+a+"/errorCorrectLevel:"+b);for(var d=c.length/3,e=[],f=0;d>f;f++)for(var g=c[3*f+0],h=c[3*f+1],i=c[3*f+2],k=0;g>k;k++)e.push(new j(h,i));return e},j.getRsBlockTable=function(a,b){switch(b){case d.L:return j.RS_BLOCK_TABLE[4*(a-1)+0];case d.M:return j.RS_BLOCK_TABLE[4*(a-1)+1];case d.Q:return j.RS_BLOCK_TABLE[4*(a-1)+2];case d.H:return j.RS_BLOCK_TABLE[4*(a-1)+3];default:return void 0}};QRCode=function(a,b){if(this._htOption={width:256,height:256,typeNumber:4,colorDark:"#000000",colorLight:"#ffffff",correctLevel:d.H},"string"==typeof b&&(b={text:b}),b)for(var c in b)this._htOption[c]=b[c];"string"==typeof a&&(a=document.getElementById(a)),this._android=n(),this._el=a,this._oQRCode=null,this._oDrawing=new q(this._el,this._htOption),this._htOption.text&&this.makeCode(this._htOption.text)},QRCode.prototype.makeCode=function(a){this._oQRCode=new b(r(a,this._htOption.correctLevel),this._htOption.correctLevel),this._oQRCode.addData(a),this._oQRCode.make(),this._el.title=a,this._oDrawing.draw(this._oQRCode),this.makeImage()},QRCode.prototype.makeImage=function(){"function"==typeof this._oDrawing.makeImage&&(!this._android||this._android>=3)&&this._oDrawing.makeImage()},QRCode.prototype.clear=function(){this._oDrawing.clear()},QRCode.CorrectLevel=d}();
/* qrcode.min.js end */
(function(){document.addEventListener('DOMContentLoaded', function(){function renderWithQRCodeLib(txt){const container=document.getElementById('qr');container.innerHTML='';try{new QRCode(container,{text:txt,width:240,height:240,colorDark:'#000000',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.H});}catch(e){container.textContent='QR generation failed';}};document.getElementById('gen').addEventListener('click',function(){const txt=document.getElementById('links').value.trim();if(!txt)return alert('Paste a link first');renderWithQRCodeLib(txt);});document.getElementById('copy').addEventListener('click',async function(){const val=document.getElementById('links').value;if(!val)return;try{await navigator.clipboard.writeText(val);alert('Copied');}catch(e){alert('Copy failed');}});document.getElementById('download').addEventListener('click',function(){const val=document.getElementById('links').value;if(!val)return;const blob=new Blob([val],{type:'text/plain'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='subscription.txt';document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);});});})();</script></body></html>`;
}
