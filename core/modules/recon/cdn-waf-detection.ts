import axios from 'axios';
import { lookup } from 'dns/promises';
import type { ScanConfiguration } from '../../config/scanner-config';

interface CDNWAFResult {
  cdn: {
    detected: boolean;
    provider?: string;
    confidence: number;
  };
  waf: {
    detected: boolean;
    provider?: string;
    confidence: number;
  };
  findings: Array<{
    type: 'cdn_detected' | 'waf_detected' | 'direct_origin_exposure';
    severity: 'info' | 'low' | 'medium';
    title: string;
    description: string;
  }>;
}

const CDN_SIGNATURES = {
  'cloudflare': {
    headers: ['cf-ray', 'cf-cache-status'],
    ips: ['173.245.48.0/20', '103.21.244.0/22']
  },
  'cloudfront': {
    headers: ['x-amz-cf-id', 'x-amz-cf-pop'],
    ips: []
  },
  'akamai': {
    headers: ['x-akamai-transformed'],
    ips: []
  },
  'fastly': {
    headers: ['x-fastly-request-id'],
    ips: []
  },
  'imperva': {
    headers: ['x-cdn', 'x-iinfo'],
    ips: []
  }
};

const WAF_SIGNATURES = {
  'cloudflare': {
    errorPages: [/cloudflare/i, /ray id/i],
    headers: ['cf-ray']
  },
  'aws-waf': {
    errorPages: [/aws/i, /access denied/i],
    headers: []
  },
  'akamai': {
    errorPages: [/akamai/i],
    headers: ['x-akamai-transformed']
  },
  'imperva': {
    errorPages: [/imperva/i, /incapsula/i],
    headers: ['x-cdn']
  },
  'f5-bigip': {
    errorPages: [/f5/i, /bigip/i],
    headers: []
  },
  'barracuda': {
    errorPages: [/barracuda/i],
    headers: []
  }
};

export async function detectCDNAndWAF(
  url: string,
  config: ScanConfiguration
): Promise<CDNWAFResult> {
  const result: CDNWAFResult = {
    cdn: { detected: false, confidence: 0 },
    waf: { detected: false, confidence: 0 },
    findings: []
  };

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;

    const response = await axios.get(url, {
      timeout: 10000,
      validateStatus: () => true,
      headers: {
        'User-Agent': config.userAgent
      }
    });

    const headers = response.headers;

    // Detect CDN
    for (const [provider, sig] of Object.entries(CDN_SIGNATURES)) {
      for (const header of sig.headers) {
        if (headers[header]) {
          result.cdn.detected = true;
          result.cdn.provider = provider;
          result.cdn.confidence = 100;

          result.findings.push({
            type: 'cdn_detected',
            severity: 'info',
            title: `CDN detected: ${provider}`,
            description: `Target is using ${provider} as CDN. Header: ${header}`
          });
          break;
        }
      }
    }

    // Detect WAF by testing a malicious payload
    if (config.intensity === 'active' || config.intensity === 'aggressive') {
      try {
        const testPayload = "?test=<script>alert('xss')</script>";
        const wafResponse = await axios.get(url + testPayload, {
          timeout: 10000,
          validateStatus: () => true,
          headers: {
            'User-Agent': config.userAgent
          }
        });

        if (wafResponse.status === 403 || wafResponse.status === 406) {
          const body = wafResponse.data;

          for (const [provider, sig] of Object.entries(WAF_SIGNATURES)) {
            for (const pattern of sig.errorPages) {
              if (pattern.test(body)) {
                result.waf.detected = true;
                result.waf.provider = provider;
                result.waf.confidence = 90;

                result.findings.push({
                  type: 'waf_detected',
                  severity: 'info',
                  title: `WAF detected: ${provider}`,
                  description: `Web Application Firewall identified: ${provider}. Some tests may be blocked.`
                });
                break;
              }
            }
          }

          if (!result.waf.detected) {
            result.waf.detected = true;
            result.waf.provider = 'unknown';
            result.waf.confidence = 70;

            result.findings.push({
              type: 'waf_detected',
              severity: 'info',
              title: 'WAF detected (unknown provider)',
              description: 'A Web Application Firewall is blocking malicious requests, but the provider could not be identified.'
            });
          }
        }
      } catch (error) {
        // WAF test failed, no WAF or network error
      }
    }

    // Check for direct origin IP exposure
    try {
      const dnsRecords = await lookup(hostname, { all: true });
      if (dnsRecords.length > 0 && result.cdn.detected) {
        result.findings.push({
          type: 'direct_origin_exposure',
          severity: 'low',
          title: 'Potential direct origin IP exposure',
          description: `CDN is in use, but origin IP may be exposed via DNS: ${dnsRecords.map(r => r.address).join(', ')}`
        });
      }
    } catch (error) {
      // DNS lookup failed
    }

  } catch (error) {
    console.error(`CDN/WAF detection error for ${url}:`, error);
  }

  return result;
}
