const WebSocket = require('ws');
const { MD5, AES, enc, mode, pad } = require('crypto-js');
const https = require('https');
const http = require('http');

let ws;
let pingInterval;

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

const handleMessage = (decodedMessage) => {
    const data = decodedMessage?.payload?.data;
    
    if (data?.bizData?.devId !== config.devId) return;
    if (data?.bizCode !== 'devicePropertyMessage') return;
    
    const props = data?.bizData?.properties || [];
    const ring = props.find(p => p.code === 'initiative_message');
    
    if (!ring) return;
    
    // Decodifica o payload base64 do toque pra extrair a foto
    let pictureInfo = null;
    try {
        const decoded = Buffer.from(ring.value, 'base64').toString('utf-8');
        pictureInfo = JSON.parse(decoded);
    } catch (e) {
        console.error('Falha ao decodificar initiative_message:', e.message);
    }
    
    // Só dispara se for evento de campainha (cmd: ipc_doorbell)
    if (pictureInfo?.cmd !== 'ipc_doorbell') {
        if (process.env.DEBUG) console.log('Evento ignorado (não é toque):', pictureInfo?.cmd);
        return;
    }
    
    console.log('>>> CAMPAINHA TOCOU <<<', { 
        time: pictureInfo.time,
        file: pictureInfo.files?.[0]?.[0],
        messageId: decodedMessage.messageId 
    });
    
    // Manda payload enxuto pro HA
    notifyHass({
        devId: data.bizData.devId,
        event: 'doorbell_ring',
        time: pictureInfo.time,
        picture_path: pictureInfo.files?.[0]?.[0] || null,
        picture_key: pictureInfo.files?.[0]?.[1] || null,
        bucket: pictureInfo.bucket
    });
}

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
