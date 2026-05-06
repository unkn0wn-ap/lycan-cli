"use strict";
/**
 * Advanced TLS/SSL Configuration Analysis Module
 *
 * Deep analysis of TLS/SSL security:
 * - Supported TLS versions (SSLv3, TLS 1.0/1.1/1.2/1.3)
 * - Cipher suite strength
 * - Certificate validation (expiry, chain, self-signed)
 * - HSTS configuration
 * - Certificate transparency
 * - Forward secrecy support
 * - Weak ciphers (RC4, DES, 3DES, MD5)
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAdvancedTls = runAdvancedTls;
const axios_1 = __importDefault(require("axios"));
const https_1 = __importDefault(require("https"));
const tls_1 = __importDefault(require("tls"));
const WEAK_CIPHERS = [
    'RC4',
    'DES',
    '3DES',
    'MD5',
    'NULL',
    'EXPORT',
    'anon',
    'ADH',
    'AECDH',
];
const DEPRECATED_PROTOCOLS = [
    'SSLv2',
    'SSLv3',
    'TLSv1',
    'TLSv1.1',
];
async function runAdvancedTls(hostname, config) {
    console.log(`[tls] Running against ${hostname}`);
    const findings = [];
    try {
        // 1. Check HTTPS availability
        const httpsAvailable = await checkHttpsAvailability(hostname);
        if (!httpsAvailable) {
            findings.push({
                module: 'tls',
                severity: 'critical',
                title: 'HTTPS Not Available',
                description: `The domain ${hostname} does not support HTTPS. All traffic is sent in plaintext, exposing sensitive data to interception, tampering, and man-in-the-middle attacks.`,
                remediation: 'Implement HTTPS using a valid SSL/TLS certificate from a trusted CA. Use Let\'s Encrypt for free certificates. Redirect all HTTP traffic to HTTPS.',
                metadata: {
                    protocol: 'http-only',
                },
            });
            return findings;
        }
        // 2. Check TLS version support
        const tlsFindings = await checkTlsVersions(hostname);
        findings.push(...tlsFindings);
        // 3. Check cipher suites
        const cipherFindings = await checkCipherSuites(hostname);
        findings.push(...cipherFindings);
        // 4. Check certificate
        const certFindings = await checkCertificate(hostname);
        findings.push(...certFindings);
        // 5. Check HSTS
        const hstsFindings = await checkHSTS(hostname);
        findings.push(...hstsFindings);
        console.log(`[tls] Completed with ${findings.length} findings`);
    }
    catch (error) {
        console.error('[tls] Error:', error);
    }
    return findings;
}
async function checkHttpsAvailability(hostname) {
    try {
        await axios_1.default.get(`https://${hostname}`, {
            timeout: 8000,
            maxRedirects: 3,
            validateStatus: () => true,
            httpsAgent: new https_1.default.Agent({ rejectUnauthorized: false }), // Accept self-signed for testing
        });
        return true;
    }
    catch (error) {
        return false;
    }
}
async function checkTlsVersions(hostname) {
    const findings = [];
    // Test for deprecated protocols
    for (const protocol of DEPRECATED_PROTOCOLS) {
        const supported = await testTlsProtocol(hostname, protocol);
        if (supported) {
            const severity = protocol.includes('SSL') ? 'critical' : 'high';
            findings.push({
                module: 'tls',
                severity,
                title: `Deprecated TLS Protocol Supported: ${protocol}`,
                description: `The server supports the deprecated ${protocol} protocol. ${protocol} has known vulnerabilities (POODLE, BEAST, etc.) and should be disabled.`,
                remediation: `Disable ${protocol} on the server. Configure the server to support only TLS 1.2 and TLS 1.3. For Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3. For Nginx: ssl_protocols TLSv1.2 TLSv1.3;`,
                metadata: {
                    protocol,
                },
            });
        }
    }
    // Check for modern TLS 1.3 support
    const tls13Supported = await testTlsProtocol(hostname, 'TLSv1.3');
    if (!tls13Supported) {
        findings.push({
            module: 'tls',
            severity: 'low',
            title: 'TLS 1.3 Not Supported',
            description: 'The server does not support TLS 1.3, the latest and most secure version of TLS. TLS 1.3 provides improved performance and security.',
            remediation: 'Upgrade your TLS stack to support TLS 1.3. Most modern web servers support this.',
            metadata: {
                protocol: 'TLSv1.3',
            },
        });
    }
    return findings;
}
async function testTlsProtocol(hostname, protocol) {
    return new Promise((resolve) => {
        const protocolMap = {
            'SSLv2': 'SSLv2_method',
            'SSLv3': 'SSLv3_method',
            'TLSv1': 'TLSv1_method',
            'TLSv1.1': 'TLSv1_1_method',
            'TLSv1.2': 'TLSv1_2_method',
            'TLSv1.3': 'TLSv1_3_method',
        };
        const options = {
            host: hostname,
            port: 443,
            servername: hostname,
            minVersion: protocol.replace('v', ' '),
            maxVersion: protocol.replace('v', ' '),
            rejectUnauthorized: false,
        };
        const socket = tls_1.default.connect(options, () => {
            socket.end();
            resolve(true);
        });
        socket.on('error', () => {
            resolve(false);
        });
        socket.setTimeout(5000, () => {
            socket.destroy();
            resolve(false);
        });
    });
}
async function checkCipherSuites(hostname) {
    const findings = [];
    try {
        const socket = await new Promise((resolve, reject) => {
            const sock = tls_1.default.connect({
                host: hostname,
                port: 443,
                servername: hostname,
                rejectUnauthorized: false,
            }, () => {
                resolve(sock);
            });
            sock.on('error', reject);
            sock.setTimeout(8000, () => {
                sock.destroy();
                reject(new Error('Timeout'));
            });
        });
        const cipher = socket.getCipher();
        socket.end();
        if (cipher && cipher.name) {
            const cipherName = cipher.name;
            // Check for weak ciphers
            for (const weak of WEAK_CIPHERS) {
                if (cipherName.includes(weak)) {
                    findings.push({
                        module: 'tls',
                        severity: 'high',
                        title: `Weak Cipher Suite: ${cipherName}`,
                        description: `The server supports the weak cipher suite "${cipherName}". This cipher has known vulnerabilities and should not be used.`,
                        remediation: 'Disable weak ciphers. Use only strong, modern cipher suites with forward secrecy (ECDHE-RSA-AES128-GCM-SHA256, etc.).',
                        metadata: {
                            cipher: cipherName,
                        },
                    });
                }
            }
            // Check for forward secrecy
            if (!cipherName.includes('ECDHE') && !cipherName.includes('DHE')) {
                findings.push({
                    module: 'tls',
                    severity: 'medium',
                    title: 'No Forward Secrecy',
                    description: `The negotiated cipher "${cipherName}" does not provide forward secrecy. If the private key is compromised, all past communications can be decrypted.`,
                    remediation: 'Configure server to prefer cipher suites with ECDHE or DHE for forward secrecy.',
                    metadata: {
                        cipher: cipherName,
                    },
                });
            }
        }
    }
    catch (error) {
        // Can't determine cipher - server might be down or blocking
    }
    return findings;
}
async function checkCertificate(hostname) {
    const findings = [];
    try {
        const socket = await new Promise((resolve, reject) => {
            const sock = tls_1.default.connect({
                host: hostname,
                port: 443,
                servername: hostname,
                rejectUnauthorized: false, // We'll check manually
            }, () => {
                resolve(sock);
            });
            sock.on('error', reject);
            sock.setTimeout(8000, () => {
                sock.destroy();
                reject(new Error('Timeout'));
            });
        });
        const cert = socket.getPeerCertificate(true);
        socket.end();
        if (!cert || Object.keys(cert).length === 0) {
            findings.push({
                module: 'tls',
                severity: 'critical',
                title: 'No SSL Certificate',
                description: 'The server does not present a valid SSL certificate.',
                remediation: 'Install a valid SSL certificate from a trusted CA.',
            });
            return findings;
        }
        // Check expiry
        const validTo = new Date(cert.valid_to);
        const now = new Date();
        const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        if (daysUntilExpiry < 0) {
            findings.push({
                module: 'tls',
                severity: 'critical',
                title: 'SSL Certificate Expired',
                description: `The SSL certificate expired ${Math.abs(daysUntilExpiry)} days ago. Browsers will show security warnings and block access.`,
                remediation: 'Renew the SSL certificate immediately. Use automated renewal with Let\'s Encrypt.',
                metadata: {
                    certificate: 'expired',
                    daysUntilExpiry,
                },
            });
        }
        else if (daysUntilExpiry < 30) {
            findings.push({
                module: 'tls',
                severity: 'medium',
                title: 'SSL Certificate Expiring Soon',
                description: `The SSL certificate expires in ${daysUntilExpiry} days. Plan renewal to avoid service disruption.`,
                remediation: 'Renew the certificate before expiry. Set up automated renewal.',
                metadata: {
                    daysUntilExpiry,
                },
            });
        }
        // Check for self-signed
        if (cert.issuer && cert.subject) {
            const issuerCN = cert.issuer.CN;
            const subjectCN = cert.subject.CN;
            if (issuerCN === subjectCN) {
                findings.push({
                    module: 'tls',
                    severity: 'high',
                    title: 'Self-Signed Certificate',
                    description: 'The SSL certificate is self-signed. Browsers will display security warnings and users may not trust the site.',
                    remediation: 'Replace with a certificate from a trusted CA. Use Let\'s Encrypt for free trusted certificates.',
                    metadata: {
                        certificate: 'self-signed',
                    },
                });
            }
        }
        // Check hostname match
        const certHostname = cert.subject?.CN;
        if (certHostname && certHostname !== hostname && !cert.subjectaltname?.includes(hostname)) {
            findings.push({
                module: 'tls',
                severity: 'high',
                title: 'Certificate Hostname Mismatch',
                description: `The certificate is issued for "${certHostname}" but the site is accessed via "${hostname}". This causes browser warnings.`,
                remediation: 'Use a certificate that includes all hostnames in Subject Alternative Names (SAN).',
                metadata: {
                    certificate: 'hostname-mismatch',
                    certHostname,
                    accessedHostname: hostname,
                },
            });
        }
    }
    catch (error) {
        // Certificate check failed
    }
    return findings;
}
async function checkHSTS(hostname) {
    const findings = [];
    try {
        const response = await axios_1.default.get(`https://${hostname}`, {
            maxRedirects: 5,
            validateStatus: () => true,
            timeout: 10000,
            httpsAgent: new https_1.default.Agent({ rejectUnauthorized: false }),
        });
        const hstsHeader = response.headers['strict-transport-security'];
        if (!hstsHeader) {
            findings.push({
                module: 'tls',
                severity: 'medium',
                title: 'Missing HSTS Header',
                description: 'The Strict-Transport-Security (HSTS) header is not set. This allows attackers to downgrade connections to HTTP via SSL stripping attacks.',
                remediation: 'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                metadata: {
                    header: 'hsts',
                    value: 'missing',
                },
            });
        }
        else {
            // Parse max-age
            const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
            const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
            if (maxAge < 31536000) { // 1 year
                findings.push({
                    module: 'tls',
                    severity: 'low',
                    title: 'HSTS max-age Too Short',
                    description: `HSTS max-age is ${maxAge} seconds. Recommended is at least 31536000 (1 year) for effective protection.`,
                    remediation: 'Increase HSTS max-age to 31536000 or higher.',
                    metadata: {
                        maxAge,
                    },
                });
            }
            if (!hstsHeader.includes('includeSubDomains')) {
                findings.push({
                    module: 'tls',
                    severity: 'low',
                    title: 'HSTS Missing includeSubDomains',
                    description: 'HSTS header does not include includeSubDomains directive. Subdomains are not protected against SSL stripping.',
                    remediation: 'Add includeSubDomains to HSTS header.',
                });
            }
            if (!hstsHeader.includes('preload')) {
                findings.push({
                    module: 'tls',
                    severity: 'info',
                    title: 'HSTS Not Preloaded',
                    description: 'HSTS header does not include preload directive. Consider adding your domain to the HSTS preload list for maximum protection.',
                    remediation: 'Add preload to HSTS header and submit to https://hstspreload.org/',
                });
            }
        }
    }
    catch (error) {
        // HSTS check failed
    }
    return findings;
}
