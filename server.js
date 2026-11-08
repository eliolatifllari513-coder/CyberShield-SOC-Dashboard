const express = require('express');
const cors = require('cors');
const net = require('net');
const http = require('http');
const https = require('https');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Helper for HTTP/HTTPS Requests
function fetchJson(url) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http;
        client.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch (e) { reject(e); }
            });
        }).on('error', err => reject(err));
    });
}

// 1. Port Scanner
function checkPort(host, port, timeout = 1200) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let status = 'CLOSED';

        socket.setTimeout(timeout);
        socket.on('connect', () => { status = 'OPEN'; socket.destroy(); });
        socket.on('timeout', () => { status = 'TIMEOUT'; socket.destroy(); });
        socket.on('error', () => { status = 'CLOSED'; });
        socket.on('close', () => resolve({ port, status }));

        socket.connect(port, host);
    });
}

app.post('/api/scan', async (req, res) => {
    const { host, ports } = req.body;
    if (!host || !ports) return res.status(400).json({ error: 'Missing parameters' });

    const portList = ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    const results = [];

    for (const port of portList) {
        const result = await checkPort(host, port);
        results.push(result);
    }
    res.json({ host, results });
});

// 2. Advanced IP Geolocation (http Fix applied)
app.post('/api/iplookup', async (req, res) => {
    const { ip } = req.body;
    try {
        const data = await fetchJson(`http://ip-api.com/json/${ip}?fields=status,message,country,city,lat,lon,isp,query`);
        res.json(data);
    } catch (e) {
        res.status(500).json({ status: 'fail', message: 'API request failed' });
    }
});

// 3. HTTP Header & Security Inspector
app.post('/api/httpcheck', (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'Missing URL' });

    const targetUrl = url.startsWith('http') ? url : `https://${url}`;

    try {
        https.get(targetUrl, (resp) => {
            const headers = resp.headers;
            res.json({
                status: resp.statusCode,
                message: resp.statusMessage,
                secure: targetUrl.startsWith('https'),
                server: headers['server'] || 'Hidden/Unknown',
                strictTransport: !!headers['strict-transport-security'],
                xFrameOptions: headers['x-frame-options'] || 'Not Set'
            });
        }).on('error', () => {
            res.json({ status: 'ERROR', message: 'Host unreachable' });
        });
    } catch (e) {
        res.status(500).json({ error: 'Invalid URL format' });
    }
});

app.listen(PORT, () => {
    console.log(`CyberShield Server running at http://localhost:${PORT}`);
});

