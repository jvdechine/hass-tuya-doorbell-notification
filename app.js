const WebSocket = require('ws');
const { MD5, AES, enc, mode, pad } = require('crypto-js');
const https = require('https');
const http = require('http');

let ws;
let pingInterval;

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SERVE_PORT = parseInt(process.env.SERVE_PORT || '3000', 10);
const PHOTOS_DIR = '/app/photos';

const TUYA_API_HOSTS = {
    CN: 'openapi.tuyacn.com',
    US: 'openapi.tuyaus.com',
    EU: 'openapi.tuyaeu.com',
    IN: 'openapi.tuyain.com',
};
const tuyaApiHost = TUYA_API_HOSTS[process.env.TUYA_REGION?.toUpperCase()];

let tuyaToken = null;
let tuyaTokenExpiry = 0;

// Garante a pasta
if (!fs.existsSync(PHOTOS_DIR)) fs.mkdirSync(PHOTOS_DIR, { recursive: true });

// === HTTP server pra servir as fotos pro HA ===
http.createServer((req, res) => {
    const filename = path.basename(req.url);
    const filepath = path.join(PHOTOS_DIR, filename);
    if (!fs.existsSync(filepath)) {
        res.writeHead(404); res.end('Not found'); return;
    }
    res.writeHead(200, { 'Content-Type': 'image/jpeg' });
    fs.createReadStream(filepath).pipe(res);
}).listen(SERVE_PORT, () => {
    console.log(`Servidor de fotos rodando na porta ${SERVE_PORT}`);
});

// === Assinatura Tuya Cloud API ===
const sha256 = (str) => crypto.createHash('sha256').update(str).digest('hex');
const hmacSha256 = (str, key) => crypto.createHmac('sha256', key).update(str).digest('hex').toUpperCase();

const tuyaSign = (method, urlPath, accessToken, body = '') => {
    const t = Date.now().toString();
    const contentSha = sha256(body);
    const stringToSign = `${method}\n${contentSha}\n\n${urlPath}`;
    const signStr = config.accessId + (accessToken || '') + t + stringToSign;
    return {
        sign: hmacSha256(signStr, config.accessKey),
        t,
    };
};

const tuyaApiCall = (method, urlPath, accessToken = '', body = '') => {
    return new Promise((resolve, reject) => {
        const { sign, t } = tuyaSign(method, urlPath, accessToken, body);
        const req = https.request({
            hostname: tuyaApiHost,
            method,
            path: urlPath,
            headers: {
                'client_id': config.accessId,
                'sign': sign,
                't': t,
                'sign_method': 'HMAC-SHA256',
                ...(accessToken ? { 'access_token': accessToken } : {}),
                'Content-Type': 'application/json',
            },
        }, (res) => {
            let data = '';
            res.on('data', c => data += c);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
            });
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
};

const getTuyaToken = async () => {
    if (tuyaToken && Date.now() < tuyaTokenExpiry) return tuyaToken;
    const r = await tuyaApiCall('GET', '/v1.0/token?grant_type=1');
    if (!r.success) throw new Error('Falha no token: ' + JSON.stringify(r));
    tuyaToken = r.result.access_token;
    tuyaTokenExpiry = Date.now() + (r.result.expire_time - 60) * 1000;
    return tuyaToken;
};

const downloadPhoto = async (bucket, filePath) => {
    const token = await getTuyaToken();
    const params = `bucket=${encodeURIComponent(bucket)}&path=${encodeURIComponent(filePath)}`;
    const urlPath = `/v1.0/iot-03/files/media/download?${params}`;
    const r = await tuyaApiCall('GET', urlPath, token);
    if (!r.success) throw new Error('Falha no download URL: ' + JSON.stringify(r));
    const signedUrl = r.result.url;
    
    return new Promise((resolve, reject) => {
        https.get(signedUrl, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error('Download HTTP ' + res.statusCode));
                return;
            }
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
        }).on('error', reject);
    });
};

const SERVERS = {
    CN: 'wss://mqe.tuyacn.com:8285/',
    US: 'wss://mqe.tuyaus.com:8285/',
    EU: 'wss://mqe.tuyaeu.com:8285/',
    IN: 'wss://mqe.tuyain.com:8285/',
};

const config = {
    accessId: process.env.TUYA_CLIENT_ID,
    accessKey: process.env.TUYA_CLIENT_SECRET,
    url: SERVERS[process.env.TUYA_REGION?.toUpperCase()],
    devId: process.env.DOORBELL_DEVICE_ID,
    hassUrl: process.env.HASS_WEBHOOK_URL,
    subscriptionType: 'Failover',
    ackTimeoutMillis: 1000,
    isStartUp: true
};

const buildTopicUrl = (websocketUrl, accessId, query) => {
    return `${websocketUrl}ws/v2/consumer/persistent/${accessId}/out/event/${accessId}-sub${query}`;
}

const buildQuery = (query) => {
    return Object.keys(query).map((key) => `${key}=${encodeURIComponent(query[key])}`).join('&');
}

const buildPassword = (accessId, accessKey) => {
    const key = MD5(accessKey).toString();
    return MD5(`${accessId}${key}`).toString().substr(8, 16);
}

const decryptData = (data, accessKey) => {
    try {
        const realKey = enc.Utf8.parse(accessKey.substring(8, 24));
        const json = AES.decrypt(data, realKey, {
            mode: mode.ECB,
            padding: pad.Pkcs7,
        });
        const dataStr = enc.Utf8.stringify(json).toString();
        return JSON.parse(dataStr);
    } catch (e) {
        return '';
    }
}

const decodeMessage = (data) => {
    const { payload, ...others } = JSON.parse(data);
    const pStr = Buffer.from(payload, 'base64').toString('utf-8');
    const pJson = JSON.parse(pStr);
    pJson.data = decryptData(pJson.data, config.accessKey);
    return { payload: pJson, ...others };
}

const notifyHass = (payload) => {
    const url = new URL(config.hassUrl);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;
    
    const options = {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    const request = client.request(options, (res) => {
        if (process.env.DEBUG) {
            console.log(`HA webhook respondeu: ${res.statusCode}`);
        }
    });
    
    request.on('error', (err) => {
        console.error('Erro ao chamar webhook HA:', err.message);
    });
    
    request.write(JSON.stringify(payload));
    request.end();
}

const handleMessage = async (decodedMessage) => {
    const data = decodedMessage?.payload?.data;
    if (data?.bizData?.devId !== config.devId) return;
    if (data?.bizCode !== 'devicePropertyMessage') return;
    
    const props = data?.bizData?.properties || [];
    const ring = props.find(p => p.code === 'initiative_message');
    if (!ring) return;
    
    let pictureInfo = null;
    try {
        pictureInfo = JSON.parse(Buffer.from(ring.value, 'base64').toString('utf-8'));
    } catch (e) {
        console.error('Falha ao decodificar initiative_message:', e.message);
        return;
    }
    if (pictureInfo?.cmd !== 'ipc_doorbell') return;
    
    const bucket = pictureInfo.bucket;
    const filePath = pictureInfo.files?.[0]?.[0];
    const decryptKey = pictureInfo.files?.[0]?.[1];
    const filename = `${pictureInfo.time}.jpg`;
    const localPath = path.join(PHOTOS_DIR, filename);
    
    console.log('>>> CAMPAINHA TOCOU <<<', { time: pictureInfo.time, file: filePath });
    
    // Tenta baixar a foto (Fase 1: SEM descriptografia)
    try {
        const photoBuffer = await downloadPhoto(bucket, filePath);
        fs.writeFileSync(localPath, photoBuffer);
        console.log(`Foto salva: ${localPath} (${photoBuffer.length} bytes)`);
    } catch (e) {
        console.error('Falha ao baixar foto:', e.message);
    }
    
    notifyHass({
        devId: data.bizData.devId,
        event: 'doorbell_ring',
        time: pictureInfo.time,
        picture_filename: filename,
        decrypt_key: decryptKey,
    });
};

const ackMessage = (ws, messageId) => {
    ws.send(JSON.stringify({ messageId }));
}

const connect = () => {

    const topicUrl = buildTopicUrl(config.url, config.accessId, `?${buildQuery({ subscriptionType: config.subscriptionType, ackTimeoutMillis: config.ackTimeoutMillis })}`)

    const password = buildPassword(config.accessId, config.accessKey);
    const username = config.accessId;

    const ws = new WebSocket(topicUrl, {
        rejectUnauthorized: false,
        headers: { username, password },
    });

    ws.on('error', () => {
        clearInterval(pingInterval);
        if(config.isStartUp) {
            connect()
        }
    });
    ws.on('open', () => {
        pingInterval = setInterval(() => ws.ping() );
    });
    ws.on('close', () => {
        clearInterval(pingInterval);
        if(config.isStartUp) {
            connect()
        }
    });

    ws.on('message', (data) => {
        const decodedMessage = decodeMessage(data);
        handleMessage(decodedMessage);
        ackMessage(ws, decodedMessage.messageId);
    });
    
    return ws;
}

const main = () => {

    const requiredEnvVariables = [ "TUYA_CLIENT_ID", "TUYA_CLIENT_SECRET", "TUYA_REGION", "DOORBELL_DEVICE_ID", "HASS_WEBHOOK_URL" ]
    const invalidEnvVariables = [];
    requiredEnvVariables.forEach(envVariable => {
        if (!envVariable) {
            invalidEnvVariables.push(envVariable);
        }
    });
    if(invalidEnvVariables.length) {
        throw (`Found these env variables to be invalid: ${invalidEnvVariables.join(', ')}`);
    }

    console.info(`All config env variables seem to exist`)

    ws = connect();
};

main();

const handleSignals = signalName => {
    console.log(`Received code ${signalName}, closing gracefuly ...`);
    config.isStartUp = false;
    ws.close();
    process.exit(0);
}

['SIGTERM', 'SIGINT', 'SIGPWR'].map(signal => process.once(signal, handleSignals));
