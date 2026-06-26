const WebSocket = require('ws');
const { MD5, AES, enc, mode, pad } = require('crypto-js');
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let ws;
let pingInterval;

const SERVERS = {
    CN: 'wss://mqe.tuyacn.com:8285/',
    US: 'wss://mqe.tuyaus.com:8285/',
    EU: 'wss://mqe.tuyaeu.com:8285/',
    IN: 'wss://mqe.tuyain.com:8285/',
};
const API_HOSTS = {
    CN: 'openapi.tuyacn.com',
    US: 'openapi.tuyaus.com',
    EU: 'openapi.tuyaeu.com',
    IN: 'openapi.tuyain.com',
};

const config = {
    accessId: process.env.TUYA_CLIENT_ID,
    accessKey: process.env.TUYA_CLIENT_SECRET,
    url: SERVERS[process.env.TUYA_REGION?.toUpperCase()],
    apiHost: API_HOSTS[process.env.TUYA_REGION?.toUpperCase()],
    devId: process.env.DOORBELL_DEVICE_ID,
    hassUrl: process.env.HASS_WEBHOOK_URL,
    servePort: parseInt(process.env.SERVE_PORT || '3000', 10),
    photosDir: '/app/photos',
    subscriptionType: 'Failover',
    ackTimeoutMillis: 1000,
    isStartUp: true,
};

let tuyaToken = null;
let tuyaTokenExpiry = 0;

// === Pasta de fotos + servidor HTTP que serve elas pro HA ===
if (!fs.existsSync(config.photosDir)) fs.mkdirSync(config.photosDir, { recursive: true });

http.createServer((req, res) => {
    const filename = path.basename(req.url || '');
    const filepath = path.join(config.photosDir, filename);
    if (!filepath.startsWith(config.photosDir) || !fs.existsSync(filepath)) {
        res.writeHead(404); res.end('Not found'); return;
    }
    res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Cache-Control': 'no-store' });
    fs.createReadStream(filepath).pipe(res);
}).listen(config.servePort, () => {
    console.log(`Servidor de fotos: porta ${config.servePort}`);
});

// === Decoder das mensagens do Pulsar (igual original) ===
const buildTopicUrl = (websocketUrl, accessId, query) =>
    `${websocketUrl}ws/v2/consumer/persistent/${accessId}/out/event/${accessId}-sub${query}`;
const buildQuery = (q) => Object.keys(q).map((k) => `${k}=${encodeURIComponent(q[k])}`).join('&');
const buildPassword = (accessId, accessKey) => {
    const key = MD5(accessKey).toString();
    return MD5(`${accessId}${key}`).toString().substr(8, 16);
};
const decryptData = (data, accessKey) => {
    try {
        const realKey = enc.Utf8.parse(accessKey.substring(8, 24));
        const json = AES.decrypt(data, realKey, { mode: mode.ECB, padding: pad.Pkcs7 });
        return JSON.parse(enc.Utf8.stringify(json).toString());
    } catch (e) { return ''; }
};
const decodeMessage = (data) => {
    const { payload, ...others } = JSON.parse(data);
    const pStr = Buffer.from(payload, 'base64').toString('utf-8');
    const pJson = JSON.parse(pStr);
    pJson.data = decryptData(pJson.data, config.accessKey);
    return { payload: pJson, ...others };
};

// === Tuya Cloud API ===
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmacSha256 = (s, k) => crypto.createHmac('sha256', k).update(s).digest('hex').toUpperCase();

const tuyaApiCall = (method, urlPath, token = '') => new Promise((resolve, reject) => {
    const t = Date.now().toString();
    const stringToSign = `${method}\n${sha256hex('')}\n\n${urlPath}`;
    const signStr = config.accessId + token + t + stringToSign;
    const sign = hmacSha256(signStr, config.accessKey);
    const headers = {
        client_id: config.accessId, sign, t,
        sign_method: 'HMAC-SHA256', 'Content-Type': 'application/json',
    };
    if (token) headers.access_token = token;

    const req = https.request({ hostname: config.apiHost, method, path: urlPath, headers }, (res) => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => { try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('parse: ' + data.substring(0, 150))); } });
    });
    req.on('error', reject);
    req.end();
});

const getTuyaToken = async () => {
    if (tuyaToken && Date.now() < tuyaTokenExpiry) return tuyaToken;
    const r = await tuyaApiCall('GET', '/v1.0/token?grant_type=1');
    if (!r.success) throw new Error('Token: ' + JSON.stringify(r));
    tuyaToken = r.result.access_token;
    tuyaTokenExpiry = Date.now() + (r.result.expire_time - 60) * 1000;
    return tuyaToken;
};

const downloadBinary = (url) => new Promise((resolve, reject) => {
    const client = url.startsWith('https:') ? https : http;
    const req = client.get(url, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
            return downloadBinary(res.headers.location).then(resolve).catch(reject);
        }
        if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
    });
    req.on('error', reject);
});

// Pipeline: obter URL → baixar → parsear header → descriptografar → salvar JPEG
const fetchAndDecryptPhoto = async (bucket, filePath, decryptKey) => {
    const token = await getTuyaToken();
    const params = `bucket=${encodeURIComponent(bucket)}&file_path=${encodeURIComponent(filePath)}`;
    const r = await tuyaApiCall('GET', `/v1.0/devices/${config.devId}/movement-configs?${params}`, token);
    if (!r.success) throw new Error('URL: ' + JSON.stringify(r));
    
    const blob = await downloadBinary(r.result);
    if (blob.length < 64) throw new Error('Arquivo pequeno demais: ' + blob.length + ' bytes');
    
    // Header: [4 bytes version][16 bytes IV][44 bytes reservado][resto = ciphertext]
    const iv = blob.subarray(4, 20);
    const ciphertext = blob.subarray(64);
    const key = Buffer.from(decryptKey, 'utf-8');
    if (key.length !== 16) throw new Error('Chave tem ' + key.length + ' bytes (esperado 16)');
    
    // Tentamos as 3 estratégias até uma produzir JPEG válido
    const tryDecrypt = (autoPad, prePad) => {
        let input = ciphertext;
        if (prePad) {
            const padLen = 16 - (ciphertext.length % 16);
            input = Buffer.concat([ciphertext, Buffer.alloc(padLen, padLen)]);
        }
        const d = crypto.createDecipheriv('aes-128-cbc', key, iv);
        d.setAutoPadding(autoPad);
        return Buffer.concat([d.update(input), d.final()]);
    };
    
    const isJpeg = (b) => b.length > 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF;
    
    for (const [name, opts] of [
        ['autopad-on', [true, false]],
        ['autopad-off', [false, false]],
        ['prepad-pkcs7', [false, true]],
    ]) {
        try {
            const out = tryDecrypt(...opts);
            if (isJpeg(out)) {
                console.log(`  ✅ descriptografado [${name}]: ${out.length} bytes`);
                return out;
            }
        } catch (e) { /* tenta a próxima */ }
    }
    throw new Error('Nenhuma estratégia produziu JPEG válido');
};

const notifyHass = (payload) => {
    const url = new URL(config.hassUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;
    const req = client.request({
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        headers: { 'Content-Type': 'application/json' },
    }, (res) => {
        if (process.env.DEBUG) console.log(`HA webhook: ${res.statusCode}`);
    });
    req.on('error', (e) => console.error('Webhook erro:', e.message));
    req.write(JSON.stringify(payload));
    req.end();
};

const handleMessage = async (decodedMessage) => {
    const data = decodedMessage?.payload?.data;
    if (data?.bizData?.devId !== config.devId) return;
    if (data?.bizCode !== 'devicePropertyMessage') return;
    
    const ring = (data?.bizData?.properties || []).find(p => p.code === 'initiative_message');
    if (!ring) return;
    
    let pictureInfo;
    try {
        pictureInfo = JSON.parse(Buffer.from(ring.value, 'base64').toString('utf-8'));
    } catch (e) { console.error('decode initiative_message:', e.message); return; }
    
    if (pictureInfo?.cmd !== 'ipc_doorbell') return;
    
    // Estrutura via Pulsar: files = [[path, key]]
    const file = pictureInfo.files?.[0];
    if (!Array.isArray(file)) {
        console.error('formato inesperado de files:', JSON.stringify(pictureInfo.files));
        return;
    }
    const [filePath, decryptKey] = file;
    const bucket = pictureInfo.bucket;
    const filename = `${pictureInfo.time}.jpg`;
    const localPath = path.join(config.photosDir, filename);
    
    console.log('>>> CAMPAINHA TOCOU <<<', { time: pictureInfo.time, file: filePath });
    
    // Dispara o webhook IMEDIATAMENTE (notificação rápida, sem foto)
    notifyHass({
        devId: data.bizData.devId,
        event: 'doorbell_ring',
        time: pictureInfo.time,
        filename,  // o HA vai usar pra montar a URL da foto
    });
    
    // Baixa e descriptografa a foto em paralelo (não bloqueia o webhook)
    try {
        const jpeg = await fetchAndDecryptPhoto(bucket, filePath, decryptKey);
        fs.writeFileSync(localPath, jpeg);
        console.log(`  💾 ${localPath} (${jpeg.length} bytes)`);
        
        // Também salva como "ultimo.jpg" pra notificação simples
        fs.writeFileSync(path.join(config.photosDir, 'ultimo.jpg'), jpeg);
    } catch (e) {
        console.error('Foto falhou:', e.message);
    }
};

const ackMessage = (ws, messageId) => ws.send(JSON.stringify({ messageId }));

const connect = () => {
    const topicUrl = buildTopicUrl(config.url, config.accessId,
        `?${buildQuery({ subscriptionType: config.subscriptionType, ackTimeoutMillis: config.ackTimeoutMillis })}`);
    const password = buildPassword(config.accessId, config.accessKey);
    const username = config.accessId;
    
    const ws = new WebSocket(topicUrl, { rejectUnauthorized: false, headers: { username, password } });
    
    ws.on('error', () => { clearInterval(pingInterval); if (config.isStartUp) connect(); });
    ws.on('open', () => { pingInterval = setInterval(() => ws.ping()); console.log('Pulsar conectado'); });
    ws.on('close', () => { clearInterval(pingInterval); if (config.isStartUp) connect(); });
    ws.on('message', (data) => {
        const decodedMessage = decodeMessage(data);
        handleMessage(decodedMessage).catch(e => console.error('handle:', e.message));
        ackMessage(ws, decodedMessage.messageId);
    });
    
    return ws;
};

const main = () => {
    const required = ['TUYA_CLIENT_ID', 'TUYA_CLIENT_SECRET', 'TUYA_REGION', 'DOORBELL_DEVICE_ID', 'HASS_WEBHOOK_URL'];
    const missing = required.filter(v => !process.env[v]);
    if (missing.length) throw new Error('Faltam env vars: ' + missing.join(', '));
    console.info('Config OK, conectando...');
    ws = connect();
};

main();

const handleSignals = (sig) => {
    console.log('Sinal:', sig);
    config.isStartUp = false;
    ws.close();
    process.exit(0);
};
['SIGTERM', 'SIGINT', 'SIGPWR'].forEach(s => process.once(s, handleSignals));
