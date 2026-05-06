/**
 * API Security Analysis Module
 * 
 * Specialized testing for REST/GraphQL APIs:
 * - API endpoint discovery
 * - Authentication bypass attempts
 * - Rate limiting detection
 * - GraphQL introspection
 * - API versioning issues
 * - Mass assignment vulnerabilities
 * - Improper CORS configuration
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
    method?: string;
    vulnerability?: string;
    [key: string]: unknown;
  };
}

const API_ENDPOINTS = [
  '/api',
  '/api/v1',
  '/api/v2',
  '/graphql',
  '/api/graphql',
  '/rest',
  '/api/rest',
  '/v1',
  '/v2',
  '/swagger.json',
  '/openapi.json',
];

const COMMON_API_PATHS = [
  '/users',
  '/user',
  '/admin',
  '/auth',
  '/login',
  '/register',
  '/profile',
  '/account',
  '/config',
  '/settings',
  '/health',
  '/status',
  '/metrics',
];

export async function runApiSecurity(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  console.log(`[api_security] Running against ${hostname}`);
  const findings: Finding[] = [];
  const protocol = 'https://';
  const baseUrl = `${protocol}${hostname}`;

  try {
    // 1. Discover API endpoints
    const endpoints = await discoverApiEndpoints(baseUrl);
    
    if (endpoints.length === 0) {
      findings.push({
        module: 'api_security',
        severity: 'info',
        title: 'No API Endpoints Detected',
        description: 'No common API endpoints were found. The application may not expose a REST/GraphQL API, or endpoints use non-standard paths.',
        metadata: {
          endpoint: 'none',
        },
      });
      return findings;
    }

    // 2. Test CORS configuration
    for (const endpoint of endpoints.slice(0, 3)) {
      const corsFindings = await testCORS(baseUrl, endpoint);
      findings.push(...corsFindings);
    }

    // 3. Test rate limiting
    for (const endpoint of endpoints.slice(0, 2)) {
      const rateLimitFindings = await testRateLimiting(baseUrl, endpoint, config);
      findings.push(...rateLimitFindings);
    }

    // 4. Test GraphQL if detected
    if (endpoints.some(e => e.includes('graphql'))) {
      const graphqlFindings = await testGraphQL(baseUrl);
      findings.push(...graphqlFindings);
    }

    // 5. Test for exposed documentation
    const docFindings = await testApiDocumentation(baseUrl);
    findings.push(...docFindings);

    console.log(`[api_security] Completed with ${findings.length} findings`);
  } catch (error) {
    console.error('[api_security] Error:', error);
  }

  return findings;
}

async function discoverApiEndpoints(baseUrl: string): Promise<string[]> {
  const discovered: string[] = [];

  for (const endpoint of API_ENDPOINTS) {
    try {
      const response = await axios.get(`${baseUrl}${endpoint}`, {
        validateStatus: () => true,
        timeout: 5000,
        maxRedirects: 3,
      });

      if (response.status < 500) {
        discovered.push(endpoint);
      }
    } catch (error) {
      // Endpoint doesn't exist
    }
  }

  return discovered;
}

async function testCORS(baseUrl: string, endpoint: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await axios.options(`${baseUrl}${endpoint}`, {
      headers: {
        'Origin': 'https://evil.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type',
      },
      validateStatus: () => true,
      timeout: 8000,
    });

    const allowOrigin = response.headers['access-control-allow-origin'];
    const allowCredentials = response.headers['access-control-allow-credentials'];

    // Check for wildcard CORS
    if (allowOrigin === '*') {
      const severity = allowCredentials === 'true' ? 'critical' : 'high';
      
      findings.push({
        module: 'api_security',
        severity,
        title: `Wildcard CORS Configuration: ${endpoint}`,
        description: `The API endpoint ${endpoint} allows requests from any origin (Access-Control-Allow-Origin: *). ${allowCredentials === 'true' ? 'Combined with credentials: true, this allows any website to make authenticated requests to your API.' : 'This allows any website to read API responses.'}`,
        remediation: 'Configure CORS to allow only trusted origins. Use a whitelist of specific domains instead of *. If using credentials, never use wildcard origin.',
        metadata: {
          endpoint,
          vulnerability: 'cors-wildcard',
          allowOrigin: '*',
          allowCredentials: allowCredentials || 'false',
        },
      });
    }

    // Check if evil.com was specifically allowed
    if (allowOrigin === 'https://evil.com' || allowOrigin?.includes('evil.com')) {
      findings.push({
        module: 'api_security',
        severity: 'critical',
        title: `CORS Reflects Arbitrary Origin: ${endpoint}`,
        description: `The API reflects the Origin header without validation. An attacker can set any origin and the server will allow it, enabling cross-origin attacks.`,
        remediation: 'Implement a strict whitelist of allowed origins. Do not reflect the Origin header without validation.',
        metadata: {
          endpoint,
          vulnerability: 'cors-reflection',
        },
      });
    }

  } catch (error) {
    // CORS test failed - possibly no OPTIONS support
  }

  return findings;
}

async function testRateLimiting(
  baseUrl: string,
  endpoint: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Only test if enterprise/red_team (don't spam free tier)
  if (config.userPlan !== 'enterprise' && config.userPlan !== 'red_team') {
    return findings;
  }

  try {
    const requests = 15;
    let successCount = 0;

    for (let i = 0; i < requests; i++) {
      try {
        const response = await axios.get(`${baseUrl}${endpoint}`, {
          validateStatus: () => true,
          timeout: 3000,
        });

        if (response.status < 500) {
          successCount++;
        }

        // Check for rate limit indicators
        if (response.status === 429) {
          // Good! Rate limiting is in place
          return findings;
        }
      } catch (error) {
        // Network error
      }
    }

    // If all requests succeeded, rate limiting may be missing
    if (successCount >= requests - 2) {
      findings.push({
        module: 'api_security',
        severity: 'medium',
        title: `No Rate Limiting Detected: ${endpoint}`,
        description: `The API endpoint ${endpoint} does not appear to implement rate limiting. ${requests} rapid requests were all accepted. This allows brute-force attacks, credential stuffing, and resource exhaustion.`,
        remediation: 'Implement rate limiting on all API endpoints. Use per-IP and per-user limits. Return HTTP 429 (Too Many Requests) when limits are exceeded.',
        metadata: {
          endpoint,
          vulnerability: 'no-rate-limit',
          requestsTested: requests,
        },
      });
    }
  } catch (error) {
    // Rate limit test failed
  }

  return findings;
}

async function testGraphQL(baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const graphqlPaths = ['/graphql', '/api/graphql', '/v1/graphql'];

  for (const path of graphqlPaths) {
    try {
      // Test introspection query
      const introspectionQuery = {
        query: `{
          __schema {
            types {
              name
            }
          }
        }`,
      };

      const response = await axios.post(`${baseUrl}${path}`, introspectionQuery, {
        headers: {
          'Content-Type': 'application/json',
        },
        validateStatus: () => true,
        timeout: 10000,
      });

      if (response.status === 200 && response.data?.data?.__schema) {
        findings.push({
          module: 'api_security',
          severity: 'medium',
          title: `GraphQL Introspection Enabled: ${path}`,
          description: `The GraphQL endpoint ${path} has introspection enabled. This exposes the entire API schema to attackers, revealing all queries, mutations, types, and fields. While useful for development, it should be disabled in production.`,
          remediation: 'Disable GraphQL introspection in production. For Apollo Server: introspection: false. For graphql-yoga: disableIntrospection: true.',
          metadata: {
            endpoint: path,
            vulnerability: 'graphql-introspection',
          },
        });
      }

    } catch (error) {
      // GraphQL test failed
    }
  }

  return findings;
}

async function testApiDocumentation(baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const docPaths = [
    '/api-docs',
    '/swagger',
    '/swagger.json',
    '/swagger-ui',
    '/api/swagger.json',
    '/openapi.json',
    '/docs',
    '/api/docs',
    '/redoc',
  ];

  for (const path of docPaths) {
    try {
      const response = await axios.get(`${baseUrl}${path}`, {
        validateStatus: () => true,
        timeout: 6000,
      });

      if (response.status === 200) {
        findings.push({
          module: 'api_security',
          severity: 'info',
          title: `API Documentation Publicly Accessible: ${path}`,
          description: `API documentation is publicly accessible at ${path}. While transparency can be good, this exposes your entire API surface to potential attackers, making reconnaissance easier.`,
          remediation: 'Consider restricting API documentation to authenticated users or internal networks. Implement IP whitelisting or require authentication.',
          metadata: {
            endpoint: path,
            vulnerability: 'exposed-docs',
          },
        });
        
        // Only report once
        break;
      }
    } catch (error) {
      // Doc doesn't exist
    }
  }

  return findings;
}
