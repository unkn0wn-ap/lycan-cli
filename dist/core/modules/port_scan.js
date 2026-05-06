"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runPortScan = runPortScan;
const net_1 = __importDefault(require("net"));
const CRITICAL_PORTS = [
    { port: 21, service: 'FTP', severity: 'critical', description: 'FTP is exposed. It transmits credentials in plaintext.', remediation: 'Disable FTP. Use SFTP or FTPS instead.' },
    { port: 23, service: 'Telnet', severity: 'critical', description: 'Telnet is exposed. It transmits all data including passwords in cleartext.', remediation: 'Disable Telnet. Use SSH instead.' },
    { port: 3306, service: 'MySQL', severity: 'critical', description: 'MySQL database port is publicly accessible.', remediation: 'Restrict MySQL to localhost or internal network via firewall rules.' },
    { port: 5432, service: 'PostgreSQL', severity: 'critical', description: 'PostgreSQL database port is publicly accessible.', remediation: 'Restrict PostgreSQL to localhost via pg_hba.conf and firewall.' },
    { port: 6379, service: 'Redis', severity: 'critical', description: 'Redis is exposed without authentication. Data loss or RCE is possible.', remediation: 'Bind Redis to 127.0.0.1 and enable requirepass in redis.conf.' },
    { port: 27017, service: 'MongoDB', severity: 'critical', description: 'MongoDB is publicly accessible. Unauthorized access possible.', remediation: 'Enable authentication and bind MongoDB to localhost.' },
    { port: 3389, service: 'RDP', severity: 'high', description: 'Remote Desktop Protocol is exposed. Brute-force and exploitation risk.', remediation: 'Restrict RDP to VPN only using firewall rules.' },
    { port: 445, service: 'SMB', severity: 'high', description: 'SMB is exposed. Vulnerable to ransomware and lateral movement attacks.', remediation: 'Block port 445 at the firewall level unless required internally.' },
    { port: 22, service: 'SSH', severity: 'medium', description: 'SSH is exposed to the internet. Brute-force attacks are common.', remediation: 'Restrict SSH via IP allowlist and disable password auth (use key-based).' },
    { port: 8080, service: 'HTTP Alt', severity: 'low', description: 'Alternate HTTP port is open. May expose admin panels or debug interfaces.', remediation: 'Close port 8080 unless explicitly required. Require authentication.' },
    { port: 8443, service: 'HTTPS Alt', severity: 'low', description: 'Alternate HTTPS port is open.', remediation: 'Review whether port 8443 is necessary in production.' },
    { port: 9200, service: 'Elasticsearch', severity: 'critical', description: 'Elasticsearch is publicly accessible. Mass data exfiltration possible.', remediation: 'Bind Elasticsearch to localhost and use X-Pack security.' },
];
function checkPort(host, port, timeoutMs = 3000) {
    return new Promise((resolve) => {
        const socket = new net_1.default.Socket();
        let resolved = false;
        socket.setTimeout(timeoutMs);
        socket.on('connect', () => { resolved = true; socket.destroy(); resolve(true); });
        socket.on('timeout', () => { socket.destroy(); if (!resolved)
            resolve(false); });
        socket.on('error', () => { if (!resolved)
            resolve(false); });
        socket.connect(port, host);
    });
}
async function runPortScan(hostname) {
    const findings = [];
    console.log(`    [port_scan] Scanning ${CRITICAL_PORTS.length} critical ports on ${hostname}`);
    // Concurrent scan with 10 at a time
    const batchSize = 10;
    for (let i = 0; i < CRITICAL_PORTS.length; i += batchSize) {
        const batch = CRITICAL_PORTS.slice(i, i + batchSize);
        const results = await Promise.all(batch.map(async (entry) => {
            const open = await checkPort(hostname, entry.port);
            return { entry, open };
        }));
        for (const { entry, open } of results) {
            if (open) {
                console.log(`    [port_scan] Port ${entry.port} (${entry.service}) is OPEN`);
                findings.push({
                    module: 'port_scan',
                    severity: entry.severity,
                    title: `Exposed Port: ${entry.port}/${entry.service}`,
                    description: entry.description,
                    remediation: entry.remediation,
                    cwe: 'CWE-200',
                });
            }
        }
    }
    if (findings.length === 0) {
        findings.push({
            module: 'port_scan',
            severity: 'info',
            title: 'No Critical Ports Exposed',
            description: 'None of the scanned critical ports are publicly accessible. Good security posture.',
        });
    }
    return findings;
}
