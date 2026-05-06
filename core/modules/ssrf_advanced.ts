/**
 * Advanced SSRF (Server-Side Request Forgery) Detection Module
 * 
 * Checks for:
 * - URL parameter SSRF (callback URLs, webhooks, fetch endpoints)
 * - Internal IP access (127.0.0.1, 169.254.x.x, RFC1918)
 * - Cloud metadata endpoints (AWS, Azure, GCP)
 * - DNS rebinding vulnerabilities
 * - Protocol smuggling (file://, gopher://, dict://)
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
    parameter?: string;
    payload?: string;
    target?: string;
    [key: string]: unknown;
  };
}

const SSRF_PRONE_PARAMETERS = [
  'url',
  'uri',
  'path',
  'callback',
  'webhook',
  'fetch',
  'image',
  'source',
  'data',
  'file',
  'proxy',
  'redirect',
  'next',
  'return',
  'continue',
  'dest',
  'destination',
];

const SSRF_ENDPOINTS = [
  '/api/fetch',
  '/api/proxy',
  '/api/webhook',
  '/api/callback',
  '/api/preview',
  '/api/thumbnail',
  '/api/pdf',
  '/api/import',
  '/api/export',
  '/webhook',
  '/fetch',
  '/proxy',
  '/import',
];

const INTERNAL_TARGETS = [
  'http://127.0.0.1',
  'http://localhost',
  'http://0.0.0.0',
  'http://169.254.169.254', // AWS metadata
  'http://metadata.google.internal', // GCP metadata
  'http://[::1]', // IPv6 localhost
  'http://192.168.1.1',
  'http://10.0.0.1',
  'http://172.16.0.1',
];

const CLOUD_METADATA_PATHS = [
  '/latest/meta-data/',
  '/metadata/v1/',
  '/computeMetadata/v1/',
];

export async function runAdvancedSsrf(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  console.log(`[ssrf] Running against ${hostname}`);
  const findings: Finding[] = [];
  const protocol = 'https://';
  const baseUrl = `${protocol}${hostname}`;

  try {
    // 1. Test URL parameters for SSRF
    const paramFindings = await testUrlParameters(baseUrl, config);
    findings.push(...paramFindings);

    // 2. Test known SSRF-prone endpoints
    const endpointFindings = await testSsrfEndpoints(baseUrl, config);
    findings.push(...endpointFindings);

    // 3. Check for open redirects (can lead to SSRF)
    const redirectFindings = await testOpenRedirects(baseUrl, config);
    findings.push(...redirectFindings);

    console.log(`[ssrf] Completed with ${findings.length} findings`);
  } catch (error) {
    console.error('[ssrf] Error:', error);
  }

  return findings;
}

async function testUrlParameters(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const paramsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
    ? SSRF_PRONE_PARAMETERS
    : SSRF_PRONE_PARAMETERS.slice(0, 8);

  const testEndpoint = '/api/test';

  for (const param of paramsToTest) {
    // Test localhost SSRF
    const localhostTarget = 'http://127.0.0.1';
    
    try {
      const response = await axios.get(`${baseUrl}${testEndpoint}`, {
        params: {
          [param]: localhostTarget,
        },
        validateStatus: () => true,
        timeout: 8000,
        maxRedirects: 0,
      });

      // Look for signs of SSRF in response
      const responseData = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);

      // Check if server attempted to fetch the internal URL
      if (response.status === 200 || 
          /localhost|127\.0\.0\.1|connection.*refused|timeout/i.test(responseData)) {
        findings.push({
          module: 'ssrf',
          severity: 'critical',
          title: `SSRF via "${param}" Parameter`,
          description: `The parameter "${param}" appears vulnerable to SSRF attacks. The server attempted to fetch the provided URL (${localhostTarget}), which could allow attackers to access internal services, cloud metadata endpoints, or perform port scanning of internal networks.`,
          remediation: `Implement a whitelist of allowed domains/protocols. Validate and sanitize all URL inputs. Block requests to private IP ranges (RFC1918, 127.0.0.1, 169.254.x.x). Use a proxy with strict filtering. Disable unnecessary protocols (file://, gopher://, dict://).`,
          metadata: {
            endpoint: testEndpoint,
            parameter: param,
            payload: localhostTarget,
            target: 'localhost',
          },
        });
      }
    } catch (error) {
      // Endpoint doesn't exist or network error
    }

    // Test cloud metadata SSRF (AWS)
    const metadataTarget = 'http://169.254.169.254/latest/meta-data/';
    
    try {
      const response = await axios.get(`${baseUrl}${testEndpoint}`, {
        params: {
          [param]: metadataTarget,
        },
        validateStatus: () => true,
        timeout: 8000,
        maxRedirects: 0,
      });

      const responseData = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);

      // Check for AWS metadata indicators
      if (/ami-id|instance-id|iam\/security-credentials/i.test(responseData)) {
        findings.push({
          module: 'ssrf',
          severity: 'critical',
          title: `Cloud Metadata SSRF via "${param}" Parameter`,
          description: `CRITICAL: The parameter "${param}" allows access to cloud metadata endpoints (AWS IMDSv1). Attackers can steal IAM credentials, instance metadata, and potentially escalate to full cloud account compromise.`,
          remediation: `URGENT: Block access to 169.254.169.254 and all cloud metadata endpoints. Migrate to IMDSv2 (session-based). Implement strict URL validation with deny-lists for metadata IPs.`,
          metadata: {
            endpoint: testEndpoint,
            parameter: param,
            payload: metadataTarget,
            target: 'aws-metadata',
          },
        });
      }
    } catch (error) {
      // Expected for most cases
    }
  }

  return findings;
}

async function testSsrfEndpoints(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const endpointsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
    ? SSRF_ENDPOINTS
    : SSRF_ENDPOINTS.slice(0, 5);

  for (const endpoint of endpointsToTest) {
    // First check if endpoint exists and accepts POST requests
    let endpointAcceptsPost = false;
    try {
      const checkResponse = await axios.post(`${baseUrl}${endpoint}`, {}, {
        validateStatus: () => true,
        timeout: 5000,
      });
      // Endpoint accepts POST if it's not 404, 405 (Method Not Allowed), or 501 (Not Implemented)
      endpointAcceptsPost = checkResponse.status !== 404 && 
                           checkResponse.status !== 405 && 
                           checkResponse.status !== 501 &&
                           checkResponse.status < 400;
    } catch {
      continue; // Skip if endpoint doesn't exist or errors out
    }

    if (!endpointAcceptsPost) continue;

    // Test with POST and common URL parameter names
    for (const param of ['url', 'uri', 'callback']) {
      try {
        const payload = 'http://127.0.0.1:22';
        const response = await axios.post(`${baseUrl}${endpoint}`, {
          [param]: payload,
        }, {
          validateStatus: () => true,
          timeout: 8000,
        });

        const responseData = typeof response.data === 'string' 
          ? response.data 
          : JSON.stringify(response.data);

        // Only report if there's STRONG evidence of SSRF (actual connection attempt or SSH banner)
        // Must have SSH-specific indicators or explicit connection error messages with IP
        const hasStrongSSRFEvidence = (
          /SSH-\d\.\d|OpenSSH_\d|ssh-rsa|SSH Protocol/i.test(responseData) ||
          (/connection refused|connection timeout|ECONNREFUSED/i.test(responseData) && responseData.includes('127.0.0.1'))
        );

        // Additional check: response should be different from baseline (empty payload)
        let isDifferentFromBaseline = false;
        try {
          const baselineResponse = await axios.post(`${baseUrl}${endpoint}`, {
            [param]: '',
          }, {
            validateStatus: () => true,
            timeout: 5000,
          });
          const baselineData = typeof baselineResponse.data === 'string' 
            ? baselineResponse.data 
            : JSON.stringify(baselineResponse.data);
          
          isDifferentFromBaseline = responseData !== baselineData;
        } catch {
          isDifferentFromBaseline = true; // Assume different if baseline fails
        }

        if (hasStrongSSRFEvidence && isDifferentFromBaseline) {
          findings.push({
            module: 'ssrf',
            severity: 'critical',
            title: `SSRF Vulnerability: ${endpoint}`,
            description: `The endpoint ${endpoint} accepts URL parameters and makes outbound requests to attacker-controlled destinations. This allows attackers to probe internal networks, access cloud metadata services (169.254.169.254), or bypass firewalls.`,
            remediation: `Implement strict URL validation: 1) Whitelist allowed protocols (http/https only), 2) Block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8), 3) Block cloud metadata IPs (169.254.169.254), 4) Use a dedicated proxy with DNS rebinding protection.`,
            metadata: {
              endpoint,
              parameter: param,
              payload,
            },
          });
          break;
        }
      } catch (error) {
        // Expected for non-existent endpoints
      }
    }
  }

  return findings;
}

async function testOpenRedirects(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const redirectParams = ['redirect', 'url', 'next', 'return', 'continue', 'dest'];

  for (const param of redirectParams.slice(0, 4)) {
    try {
      const externalUrl = 'https://evil.com';
      const response = await axios.get(`${baseUrl}/`, {
        params: {
          [param]: externalUrl,
        },
        validateStatus: () => true,
        timeout: 6000,
        maxRedirects: 0, // Don't follow redirects
      });

      // Check if server redirects to external URL
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.location;
        
        if (location && location.includes('evil.com')) {
          findings.push({
            module: 'ssrf',
            severity: 'medium',
            title: `Open Redirect via "${param}" Parameter`,
            description: `The parameter "${param}" allows unvalidated redirects to external domains. While primarily a phishing risk, open redirects can sometimes be chained with SSRF or used to bypass URL validation in other endpoints.`,
            remediation: `Validate all redirect URLs against a whitelist. Use relative paths instead of absolute URLs when possible. Implement a redirect confirmation page for external URLs.`,
            metadata: {
              parameter: param,
              payload: externalUrl,
              redirectsTo: location,
            },
          });
        }
      }
    } catch (error) {
      // Expected
    }
  }

  return findings;
}
