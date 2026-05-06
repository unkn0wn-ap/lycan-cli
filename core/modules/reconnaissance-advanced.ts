import dns from 'dns/promises';
import type { ScanConfiguration } from '../config/scanner-config';
import { makeIdentifiedRequest } from '../config/scanner-config';
import { performFingerprinting } from './recon/fingerprinting';
import { detectCDNAndWAF } from './recon/cdn-waf-detection';
import { enumerateSubdomains } from './recon/subdomain-enum';
import { checkInfoDisclosure } from './recon/info-disclosure';

interface Finding {
  module: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  cwe?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Advanced Reconnaissance Module
 * 
 * Comprehensive information gathering including:
 * - DNS records and email security (SPF, DMARC, DKIM)
 * - Technology fingerprinting (frameworks, CMS, libraries, versions)
 * - CDN and WAF detection
 * - Subdomain enumeration
 * - Information disclosure (sensitive files, directories)
 * - Infrastructure analysis
 */
export async function runAdvancedReconnaissance(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  console.log(`  [recon] Advanced reconnaissance against ${hostname}`);
  console.log(`  [recon] Mode: ${config.intensity} | Plan: ${config.userPlan}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. DNS Records Analysis (Always enabled)
  // ═══════════════════════════════════════════════════════════════════════════
  
  try {
    const [mx, txt, ns, a, aaaa] = await Promise.all([
      dns.resolveMx(hostname).catch(() => []),
      dns.resolveTxt(hostname).catch(() => []),
      dns.resolveNs(hostname).catch(() => []),
      dns.resolve4(hostname).catch(() => []),
      dns.resolve6(hostname).catch(() => []),
    ]);

    // Check for missing MX records
    if (mx.length === 0) {
      findings.push({
        module: 'reconnaissance',
        severity: 'info',
        title: 'No MX Records Found',
        description: `${hostname} has no MX records configured. Email delivery may be misconfigured or the domain may not use email services.`,
        cwe: 'CWE-358',
        metadata: { dnsRecordType: 'MX' },
      });
    }

    // Check for SPF record
    const spfRecord = txt.flat().find((r) => r.startsWith('v=spf1'));
    if (!spfRecord && mx.length > 0) {
      findings.push({
        module: 'reconnaissance',
        severity: 'medium',
        title: 'Missing SPF Record',
        description: `No SPF (Sender Policy Framework) TXT record found for ${hostname}. Without SPF, email spoofers can impersonate your domain, and recipient servers cannot verify legitimate senders.`,
        remediation: 'Add a TXT record: v=spf1 include:_spf.google.com ~all (adjust for your email provider). Use SPF record generators and testing tools.',
        cwe: 'CWE-290',
        metadata: { mxRecords: mx.map(m => m.exchange) },
      });
    } else if (spfRecord) {
      // Analyze SPF configuration
      if (spfRecord.includes('+all') || spfRecord.includes('?all')) {
        findings.push({
          module: 'reconnaissance',
          severity: 'high',
          title: 'Permissive SPF Configuration',
          description: `SPF record is configured with ${spfRecord.includes('+all') ? '+all' : '?all'}, which allows ANY server to send email on behalf of your domain. This defeats the purpose of SPF.`,
          remediation: 'Change to ~all (soft fail) or -all (hard fail). Example: v=spf1 include:_spf.google.com -all',
          cwe: 'CWE-290',
          metadata: { spfRecord },
        });
      }
    }

    // Check for DMARC record
    const dmarc = await dns.resolveTxt(`_dmarc.${hostname}`).catch(() => []);
    if (dmarc.length === 0 && mx.length > 0) {
      findings.push({
        module: 'reconnaissance',
        severity: 'medium',
        title: 'Missing DMARC Record',
        description: `No DMARC policy found for ${hostname}. DMARC builds on SPF and DKIM to prevent email spoofing and phishing. Without it, you have no visibility into email authentication failures and cannot instruct receiving servers on how to handle failed authentication.`,
        remediation: 'Add: _dmarc.example.com TXT "v=DMARC1;p=quarantine;rua=mailto:dmarc@example.com;ruf=mailto:forensics@example.com;pct=100"',
        cwe: 'CWE-290',
      });
    } else if (dmarc.length > 0) {
      const dmarcRecord = dmarc.flat().join('');
      if (dmarcRecord.includes('p=none')) {
        findings.push({
          module: 'reconnaissance',
          severity: 'low',
          title: 'DMARC Policy Set to None',
          description: 'DMARC policy is set to "p=none", which only monitors but does not enforce email authentication. While better than no DMARC, this provides no protection against spoofing.',
          remediation: 'After monitoring reports, gradually move to p=quarantine and eventually p=reject for maximum protection.',
          cwe: 'CWE-290',
          metadata: { dmarcRecord },
        });
      }
    }

    // Check for DKIM selector (common ones)
    const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 's1'];
    let dkimFound = false;
    for (const selector of dkimSelectors) {
      try {
        const dkim = await dns.resolveTxt(`${selector}._domainkey.${hostname}`);
        if (dkim.length > 0) {
          dkimFound = true;
          break;
        }
      } catch {
        // Selector doesn't exist, continue
      }
    }

    if (!dkimFound && mx.length > 0) {
      findings.push({
        module: 'reconnaissance',
        severity: 'low',
        title: 'DKIM Not Detected',
        description: 'No DKIM (DomainKeys Identified Mail) records found using common selectors. DKIM provides cryptographic authentication for email, complementing SPF and DMARC.',
        remediation: 'Configure DKIM signing in your email provider and publish the public key as a TXT record at selector._domainkey.example.com',
        cwe: 'CWE-290',
      });
    }

    console.log(`    [recon] DNS: A=${a.length}, AAAA=${aaaa.length}, NS=${ns.length}, MX=${mx.length}, TXT=${txt.length}`);
    
  } catch (err) {
    console.error('[recon] DNS analysis error:', err);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. Technology Fingerprinting (Always enabled)
  // ═══════════════════════════════════════════════════════════════════════════
  
  if (config.recon?.technologyFingerprinting) {
    try {
      const url = `https://${hostname}`;
      const fpResult = await performFingerprinting(url, config);
      
      // Convert fingerprinting results to findings
      for (const tech of fpResult.technologies) {
        findings.push({
          module: 'reconnaissance',
          severity: 'info',
          title: `Technology Detected: ${tech.name}`,
          description: tech.version 
            ? `Detected ${tech.category} technology: ${tech.name} version ${tech.version} (confidence: ${tech.confidence}%)`
            : `Detected ${tech.category} technology: ${tech.name} (confidence: ${tech.confidence}%)`,
          metadata: { technology: tech }
        });
      }
      
      findings.push(...fpResult.findings.map(f => ({
        ...f,
        module: 'reconnaissance',
      })));
    } catch (err) {
      console.error('[recon] Technology fingerprinting error:', err);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. CDN and WAF Detection (Always enabled)
  // ═══════════════════════════════════════════════════════════════════════════
  
  if (config.recon?.cdnWafDetection) {
    try {
      const url = `https://${hostname}`;
      const cdnWafResult = await detectCDNAndWAF(url, config);
      
      findings.push(...cdnWafResult.findings.map(f => ({
        ...f,
        module: 'reconnaissance',
      })));
    } catch (err) {
      console.error('[recon] CDN/WAF detection error:', err);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. Subdomain Enumeration (Basic and above)
  // ═══════════════════════════════════════════════════════════════════════════
  
  if (config.recon?.subdomainEnumeration) {
    try {
      const subdomainResult = await enumerateSubdomains(hostname, config);
      
      findings.push(...subdomainResult.findings.map(f => ({
        ...f,
        module: 'reconnaissance',
      })));
    } catch (err) {
      console.error('[recon] Subdomain enumeration error:', err);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. Information Disclosure (Basic and above)
  // ═══════════════════════════════════════════════════════════════════════════
  
  if (config.recon?.informationDisclosure) {
    try {
      const url = `https://${hostname}`;
      const infoResult = await checkInfoDisclosure(url, config);
      
      findings.push(...infoResult.findings.map(f => ({
        ...f,
        module: 'reconnaissance',
      })));
    } catch (err) {
      console.error('[recon] Information disclosure check error:', err);
    }
  }

  console.log(`  [recon] Completed with ${findings.length} findings`);
  return findings;
}
