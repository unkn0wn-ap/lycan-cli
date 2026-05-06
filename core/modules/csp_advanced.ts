/**
 * Advanced CSP (Content Security Policy) Analysis Module
 * 
 * Deep analysis of CSP headers:
 * - CSP directive completeness
 * - Unsafe directives (unsafe-inline, unsafe-eval)
 * - Wildcard sources
 * - Missing directives (frame-ancestors, base-uri)
 * - CSP bypass techniques
 * - Report-URI/report-to configuration
 * - Upgrade-insecure-requests
 */

import axios from 'axios';
import type { ScanConfiguration } from '../config/scanner-config';

interface Finding {
  module: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  metadata?: {
    directive?: string;
    value?: string;
    bypass?: string;
    [key: string]: unknown;
  };
}

interface CSPDirectives {
  'default-src'?: string[];
  'script-src'?: string[];
  'style-src'?: string[];
  'img-src'?: string[];
  'font-src'?: string[];
  'connect-src'?: string[];
  'frame-src'?: string[];
  'frame-ancestors'?: string[];
  'base-uri'?: string[];
  'form-action'?: string[];
  'object-src'?: string[];
  'media-src'?: string[];
  'worker-src'?: string[];
  'manifest-src'?: string[];
  'report-uri'?: string[];
  'report-to'?: string[];
  'upgrade-insecure-requests'?: boolean;
  'block-all-mixed-content'?: boolean;
  [key: string]: string[] | boolean | undefined;
}

const CRITICAL_DIRECTIVES = [
  'default-src',
  'script-src',
  'object-src',
  'base-uri',
  'frame-ancestors',
];

const UNSAFE_VALUES = [
  'unsafe-inline',
  'unsafe-eval',
  'unsafe-hashes',
];

export async function runAdvancedCsp(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  console.log(`[csp] Running against ${hostname}`);
  const findings: Finding[] = [];
  const protocol = 'https://';
  const baseUrl = `${protocol}${hostname}`;

  try {
    const response = await axios.get(baseUrl, {
      maxRedirects: 5,
      validateStatus: () => true,
      timeout: 10000,
    });

    const cspHeader = response.headers['content-security-policy'] ||
                     response.headers['content-security-policy-report-only'];

    if (!cspHeader) {
      findings.push({
        module: 'csp',
        severity: 'high',
        title: 'Missing Content Security Policy',
        description: 'The application does not implement a Content Security Policy (CSP) header. CSP is a critical defense-in-depth mechanism against XSS, clickjacking, and code injection attacks.',
        remediation: 'Implement a strict Content Security Policy. Start with: Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\'; upgrade-insecure-requests',
        metadata: {
          directive: 'csp',
          value: 'missing',
        },
      });
      return findings;
    }

    // Parse CSP
    const directives = parseCSP(cspHeader);
    
    // Check for missing critical directives
    findings.push(...checkMissingDirectives(directives));

    // Check for unsafe directives
    findings.push(...checkUnsafeDirectives(directives));

    // Check for wildcards
    findings.push(...checkWildcards(directives));

    // Check for CSP bypasses
    findings.push(...checkCSPBypasses(directives));

    // Check for reporting
    findings.push(...checkReporting(directives));

    // Check for secure transport
    findings.push(...checkSecureTransport(directives));

    console.log(`[csp] Completed with ${findings.length} findings`);
  } catch (error) {
    console.error('[csp] Error:', error);
  }

  return findings;
}

function parseCSP(cspHeader: string): CSPDirectives {
  const directives: CSPDirectives = {};
  
  const parts = cspHeader.split(';').map(p => p.trim()).filter(p => p);
  
  for (const part of parts) {
    const [directiveName, ...values] = part.split(/\s+/);
    const directive = directiveName.toLowerCase();
    
    if (directive === 'upgrade-insecure-requests' || directive === 'block-all-mixed-content') {
      directives[directive] = true;
    } else if (values.length > 0) {
      directives[directive] = values.map(v => v.toLowerCase());
    }
  }
  
  return directives;
}

function checkMissingDirectives(directives: CSPDirectives): Finding[] {
  const findings: Finding[] = [];
  
  for (const critical of CRITICAL_DIRECTIVES) {
    if (!directives[critical]) {
      const severity = critical === 'default-src' ? 'high' : 
                      critical === 'script-src' ? 'high' :
                      critical === 'object-src' ? 'medium' : 'medium';
      
      findings.push({
        module: 'csp',
        severity,
        title: `Missing CSP Directive: ${critical}`,
        description: `The Content Security Policy does not include the "${critical}" directive. This directive is critical for preventing various attack vectors.`,
        remediation: `Add "${critical}" directive to your CSP. Example: ${critical} 'self'`,
        metadata: {
          directive: critical,
          value: 'missing',
        },
      });
    }
  }
  
  return findings;
}

function checkUnsafeDirectives(directives: CSPDirectives): Finding[] {
  const findings: Finding[] = [];
  
  for (const [directive, values] of Object.entries(directives)) {
    if (Array.isArray(values)) {
      for (const unsafeValue of UNSAFE_VALUES) {
        if (values.includes(`'${unsafeValue}'`) || values.includes(unsafeValue)) {
          const severity = unsafeValue === 'unsafe-eval' ? 'high' : 
                          unsafeValue === 'unsafe-inline' && directive === 'script-src' ? 'high' : 'medium';
          
          findings.push({
            module: 'csp',
            severity,
            title: `Unsafe CSP Value: ${unsafeValue} in ${directive}`,
            description: `The CSP directive "${directive}" contains "${unsafeValue}", which significantly weakens the policy. This allows execution of inline scripts/styles or eval(), defeating the purpose of CSP.`,
            remediation: `Remove "${unsafeValue}" from ${directive}. Use nonces or hashes for inline scripts: script-src 'nonce-{random}' or 'sha256-{hash}'. Refactor code to avoid eval().`,
            metadata: {
              directive,
              value: unsafeValue,
            },
          });
        }
      }
    }
  }
  
  return findings;
}

function checkWildcards(directives: CSPDirectives): Finding[] {
  const findings: Finding[] = [];
  
  for (const [directive, values] of Object.entries(directives)) {
    if (Array.isArray(values)) {
      // Check for wildcard *
      if (values.includes('*')) {
        findings.push({
          module: 'csp',
          severity: 'high',
          title: `Wildcard Source in ${directive}`,
          description: `The CSP directive "${directive}" allows all sources via wildcard (*). This completely bypasses CSP protection for this directive.`,
          remediation: `Replace wildcard with specific trusted domains. Example: ${directive} 'self' https://trusted.example.com`,
          metadata: {
            directive,
            value: '*',
          },
        });
      }
      
      // Check for https: wildcard
      if (values.includes('https:')) {
        findings.push({
          module: 'csp',
          severity: 'medium',
          title: `HTTPS Wildcard in ${directive}`,
          description: `The directive "${directive}" allows all HTTPS sources. While better than *, this still allows any HTTPS domain, including attacker-controlled sites.`,
          remediation: `Replace https: with specific trusted domains.`,
          metadata: {
            directive,
            value: 'https:',
          },
        });
      }
      
      // Check for data: in script-src
      if (directive === 'script-src' && values.includes('data:')) {
        findings.push({
          module: 'csp',
          severity: 'high',
          title: 'Data URIs Allowed in script-src',
          description: 'The script-src directive allows data: URIs, which can be used to execute arbitrary JavaScript via base64-encoded scripts.',
          remediation: 'Remove data: from script-src. Use nonces or hashes instead.',
          metadata: {
            directive,
            value: 'data:',
            bypass: 'data-uri-xss',
          },
        });
      }
    }
  }
  
  return findings;
}

function checkCSPBypasses(directives: CSPDirectives): Finding[] {
  const findings: Finding[] = [];
  const scriptSrc = directives['script-src'] || directives['default-src'] || [];
  
  if (Array.isArray(scriptSrc)) {
    // Check for common CDN bypasses
    const dangerousCDNs = [
      'cdnjs.cloudflare.com',
      'ajax.googleapis.com',
      'code.jquery.com',
      'unpkg.com',
      'cdn.jsdelivr.net',
    ];
    
    for (const cdn of dangerousCDNs) {
      if (scriptSrc.some(src => src.includes(cdn))) {
        findings.push({
          module: 'csp',
          severity: 'medium',
          title: `Potentially Bypassable CDN: ${cdn}`,
          description: `The CSP allows scripts from ${cdn}. This CDN hosts user-uploaded content or has known CSP bypass techniques via JSONP endpoints or outdated libraries.`,
          remediation: `Host scripts locally or use Subresource Integrity (SRI): <script src="..." integrity="sha384-..." crossorigin="anonymous">. Consider removing ${cdn} from CSP.`,
          metadata: {
            directive: 'script-src',
            value: cdn,
            bypass: 'cdn-jsonp',
          },
        });
      }
    }
  }
  
  return findings;
}

function checkReporting(directives: CSPDirectives): Finding[] {
  const findings: Finding[] = [];
  
  if (!directives['report-uri'] && !directives['report-to']) {
    findings.push({
      module: 'csp',
      severity: 'info',
      title: 'CSP Reporting Not Configured',
      description: 'The CSP does not include report-uri or report-to directives. CSP violation reports help detect attacks and policy misconfigurations.',
      remediation: 'Add report-uri or report-to directive to collect CSP violation reports. Use a service like report-uri.com or implement your own endpoint.',
      metadata: {
        directive: 'report-uri',
        value: 'missing',
      },
    });
  }
  
  return findings;
}

function checkSecureTransport(directives: CSPDirectives): Finding[] {
  const findings: Finding[] = [];
  
  if (!directives['upgrade-insecure-requests']) {
    findings.push({
      module: 'csp',
      severity: 'low',
      title: 'Missing upgrade-insecure-requests',
      description: 'The CSP does not include upgrade-insecure-requests directive. This directive automatically upgrades HTTP requests to HTTPS.',
      remediation: 'Add upgrade-insecure-requests to your CSP to ensure all resources are loaded over HTTPS.',
      metadata: {
        directive: 'upgrade-insecure-requests',
        value: 'missing',
      },
    });
  }
  
  return findings;
}
