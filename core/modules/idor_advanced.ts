/**
 * Advanced IDOR (Insecure Direct Object Reference) Detection Module
 * 
 * Checks for:
 * - Sequential numeric IDs in URLs/APIs
 * - Predictable resource identifiers
 * - Missing authorization checks
 * - Object enumeration vulnerabilities
 * - UUID vs sequential ID usage
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
    idType?: string;
    pattern?: string;
    accessible?: boolean;
    [key: string]: unknown;
  };
}

const IDOR_PRONE_ENDPOINTS = [
  '/api/user/{id}',
  '/api/users/{id}',
  '/api/profile/{id}',
  '/api/account/{id}',
  '/api/document/{id}',
  '/api/file/{id}',
  '/api/order/{id}',
  '/api/invoice/{id}',
  '/api/message/{id}',
  '/api/post/{id}',
  '/user/{id}',
  '/profile/{id}',
  '/document/{id}',
  '/order/{id}',
  '/admin/user/{id}',
];

export async function runAdvancedIdor(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  console.log(`[idor] Running against ${hostname}`);
  const findings: Finding[] = [];
  const protocol = 'https://';
  const baseUrl = `${protocol}${hostname}`;

  try {
    // 1. Test common IDOR-prone endpoints
    const endpointFindings = await testIdorEndpoints(baseUrl, config);
    findings.push(...endpointFindings);

    // 2. Check API documentation for ID exposure
    const apiFindings = await checkApiDocumentation(baseUrl);
    findings.push(...apiFindings);

    // 3. Test for sequential ID enumeration
    const enumerationFindings = await testIdEnumeration(baseUrl, config);
    findings.push(...enumerationFindings);

    console.log(`[idor] Completed with ${findings.length} findings`);
  } catch (error) {
    console.error('[idor] Error:', error);
  }

  return findings;
}

async function testIdorEndpoints(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const endpointsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
    ? IDOR_PRONE_ENDPOINTS
    : IDOR_PRONE_ENDPOINTS.slice(0, 6);

  for (const endpointTemplate of endpointsToTest) {
    try {
      // Test with sequential IDs
      const testIds = ['1', '2', '100', '1000'];
      const responses: { id: string; status: number; accessible: boolean }[] = [];

      for (const testId of testIds) {
        const endpoint = endpointTemplate.replace('{id}', testId);
        
        try {
          const response = await axios.get(`${baseUrl}${endpoint}`, {
            validateStatus: () => true,
            timeout: 6000,
            maxRedirects: 3,
          });

          responses.push({
            id: testId,
            status: response.status,
            accessible: response.status >= 200 && response.status < 300,
          });

          // If we get 200 OK for numeric IDs, it's potentially vulnerable
          if (response.status === 200) {
            const idType = /^\d+$/.test(testId) ? 'sequential-numeric' : 'other';
            
            findings.push({
              module: 'idor',
              severity: 'high',
              title: `Potential IDOR at ${endpointTemplate}`,
              description: `The endpoint ${endpointTemplate} uses sequential numeric IDs and responds with HTTP 200 to unauthenticated requests. This pattern is commonly vulnerable to IDOR attacks where attackers can access other users' data by incrementing/decrementing the ID parameter.`,
              remediation: `Implement proper authorization checks to verify that the requesting user has permission to access the requested resource. Use UUIDs instead of sequential IDs. Implement indirect object references (mapping tables).`,
              metadata: {
                endpoint: endpoint,
                idType,
                pattern: 'sequential',
                accessible: true,
                testedId: testId,
              },
            });
            break; // One finding per endpoint is enough
          }
        } catch (error) {
          // Endpoint doesn't exist or network error
        }
      }

      // Check if multiple sequential IDs are accessible
      const accessibleCount = responses.filter(r => r.accessible).length;
      if (accessibleCount >= 2) {
        findings.push({
          module: 'idor',
          severity: 'critical',
          title: `Sequential ID Enumeration Possible: ${endpointTemplate}`,
          description: `Multiple sequential IDs (${accessibleCount}/${testIds.length}) were accessible at ${endpointTemplate}. This confirms the endpoint is vulnerable to ID enumeration attacks, allowing attackers to iterate through all resources.`,
          remediation: `Add authorization checks, use UUIDs, implement rate limiting on enumeration attempts, and add audit logging for suspicious access patterns.`,
          metadata: {
            endpoint: endpointTemplate,
            enumerableIds: accessibleCount,
            totalTested: testIds.length,
          },
        });
      }
    } catch (error) {
      // Skip this endpoint
    }
  }

  return findings;
}

async function checkApiDocumentation(baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const commonApiDocs = [
    '/api-docs',
    '/swagger',
    '/swagger.json',
    '/swagger-ui',
    '/api/swagger.json',
    '/v1/api-docs',
    '/openapi.json',
    '/docs',
  ];

  for (const docPath of commonApiDocs) {
    try {
      const response = await axios.get(`${baseUrl}${docPath}`, {
        validateStatus: () => true,
        timeout: 6000,
      });

      if (response.status === 200) {
        const content = typeof response.data === 'string' 
          ? response.data 
          : JSON.stringify(response.data);

        // Check for ID parameters in API documentation
        const hasIdParams = /\{id\}|\{userId\}|\{orderId\}|"id"|"user_id"/i.test(content);
        const hasUuid = /uuid|guid/i.test(content);

        if (hasIdParams && !hasUuid) {
          findings.push({
            module: 'idor',
            severity: 'medium',
            title: 'API Documentation Exposes ID-Based Endpoints',
            description: `API documentation at ${docPath} reveals endpoints using ID-based parameters without apparent UUID/GUID usage. This indicates potential IDOR vulnerability.`,
            remediation: `Review all documented endpoints for proper authorization. Migrate to UUIDs for resource identification.`,
            metadata: {
              endpoint: docPath,
              idType: 'sequential-likely',
            },
          });
        }

        // Info finding about exposed API docs
        findings.push({
          module: 'idor',
          severity: 'info',
          title: 'API Documentation Publicly Accessible',
          description: `API documentation is publicly accessible at ${docPath}. While not a direct vulnerability, it provides attackers with a complete map of your API surface.`,
          remediation: `Consider restricting API documentation to authenticated users or internal networks only.`,
          metadata: {
            endpoint: docPath,
          },
        });

        break; // Found one, no need to check others
      }
    } catch (error) {
      // Doc doesn't exist
    }
  }

  return findings;
}

async function testIdEnumeration(
  baseUrl: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    // Test common patterns
    const testPaths = [
      '/api/users/1',
      '/api/user/1',
      '/user/1',
      '/profile/1',
    ];

    for (const path of testPaths) {
      try {
        const firstResponse = await axios.get(`${baseUrl}${path}`, {
          validateStatus: () => true,
          timeout: 5000,
        });

        if (firstResponse.status === 200) {
          // Try next ID
          const nextPath = path.replace('/1', '/2');
          const secondResponse = await axios.get(`${baseUrl}${nextPath}`, {
            validateStatus: () => true,
            timeout: 5000,
          });

          if (secondResponse.status === 200) {
            // Both accessible - enumeration possible
            findings.push({
              module: 'idor',
              severity: 'high',
              title: `User Enumeration via Sequential IDs: ${path}`,
              description: `The endpoint ${path} allows enumeration of users/resources through sequential ID iteration. Both ID=1 and ID=2 returned successful responses.`,
              remediation: `Implement authorization checks, use non-sequential UUIDs, add rate limiting, and return consistent error messages for both unauthorized and non-existent resources.`,
              metadata: {
                endpoint: path,
                pattern: 'sequential-enumeration',
                verified: true,
              },
            });
            break; // Found one instance
          }
        }
      } catch (error) {
        // Path doesn't exist
      }
    }
  } catch (error) {
    console.error('[idor] Enumeration test error:', error);
  }

  return findings;
}
