import dns from 'dns/promises';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

interface Finding {
  module: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  cwe?: string;
}

export async function runReconnaissance(hostname: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // 1. DNS Records
  try {
    const mx = await dns.resolveMx(hostname).catch(() => []);
    const txt = await dns.resolveTxt(hostname).catch(() => []);
    const ns  = await dns.resolveNs(hostname).catch(() => []);

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
    const dmarc = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
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
  } catch (err) {
    console.error('[recon] DNS error:', err);
  }

  return findings;
}
