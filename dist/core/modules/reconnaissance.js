"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runReconnaissance = runReconnaissance;
const promises_1 = __importDefault(require("dns/promises"));
const child_process_1 = require("child_process");
const util_1 = require("util");
const execFileAsync = (0, util_1.promisify)(child_process_1.execFile);
async function runReconnaissance(hostname) {
    const findings = [];
    // 1. DNS Records
    try {
        const mx = await promises_1.default.resolveMx(hostname).catch(() => []);
        const txt = await promises_1.default.resolveTxt(hostname).catch(() => []);
        const ns = await promises_1.default.resolveNs(hostname).catch(() => []);
        if (mx.length === 0) {
            findings.push({
                module: 'reconnaissance',
                severity: 'info',
                title: 'No MX Records Found',
                description: `${hostname} has no MX records configured. Email delivery may be misconfigured.`,
                cwe: 'CWE-358',
            });
        }
        // Check for missing SPF
        const spfRecord = txt.flat().find((r) => r.startsWith('v=spf1'));
        if (!spfRecord) {
            findings.push({
                module: 'reconnaissance',
                severity: 'medium',
                title: 'Missing SPF Record',
                description: `No SPF (Sender Policy Framework) TXT record found for ${hostname}. This allows email spoofing.`,
                remediation: 'Add a TXT record: v=spf1 include:_spf.google.com ~all (or appropriate provider)',
                cwe: 'CWE-290',
            });
        }
        // Check for missing DMARC
        const dmarc = await promises_1.default.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
        if (dmarc.length === 0) {
            findings.push({
                module: 'reconnaissance',
                severity: 'medium',
                title: 'Missing DMARC Record',
                description: `No DMARC policy found for ${hostname}. Phishing attacks using your domain are not blocked.`,
                remediation: 'Add: _dmarc.example.com TXT "v=DMARC1;p=quarantine;rua=mailto:dmarc@example.com"',
                cwe: 'CWE-290',
            });
        }
        console.log(`    [recon] NS: ${ns.length}, MX: ${mx.length}, TXT: ${txt.length}`);
    }
    catch (err) {
        console.error('[recon] DNS error:', err);
    }
    return findings;
}
