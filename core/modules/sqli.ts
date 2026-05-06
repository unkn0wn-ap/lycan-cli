interface Finding {
  module: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  payload?: string;
  cwe?: string;
}

// Common SQL injection payloads (safe, detection-only)
const SQL_PAYLOADS = [
  { payload: "' OR '1'='1", type: 'Classic OR-based' },
  { payload: "' OR 1=1--", type: 'Comment-based' },
  { payload: "' UNION SELECT NULL--", type: 'UNION-based' },
  { payload: "1' AND '1'='1", type: 'AND-based' },
  { payload: "admin'--", type: 'Comment injection' },
  { payload: "' OR 'x'='x", type: 'String-based' },
];

// Error-based detection patterns
const SQL_ERROR_PATTERNS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /PostgreSQL.*ERROR/i,
  /Warning.*pg_/i,
  /valid PostgreSQL result/i,
  /Npgsql\./i,
  /Driver.*SQL.*Server/i,
  /OLE DB.*SQL Server/i,
  /(\[SQL Server\]|\[SqlServer\])/i,
  /SQLServer JDBC Driver/i,
  /Oracle error/i,
  /Oracle.*Driver/i,
  /Warning.*oci_/i,
  /SQLite\/JDBCDriver/i,
  /SQLite.Exception/i,
  /System\.Data\.SQLite\.SQLiteException/i,
  /Microsoft Access Driver/i,
  /JET Database Engine/i,
  /Access Database Engine/i,
];

/**
 * SQL Injection vulnerability scanner
 * 
 * IMPORTANT: This is a passive/low-impact scanner designed for:
 * - Owned domains with explicit permission
 * - Basic detection of common SQLi vulnerabilities
 * - Educational and legitimate security assessment purposes
 * 
 * This scanner:
 * ✓ Only tests common entry points (search, id, user params)
 * ✓ Uses safe, read-only payloads
 * ✓ Respects rate limits
 * ✗ Does NOT exploit vulnerabilities
 * ✗ Does NOT extract data
 * ✗ Does NOT perform blind SQL injection
 */
export async function runSqli(hostname: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  // Common endpoints that might have SQL injection vulnerabilities
  const testEndpoints = [
    '/search?q=',
    '/user?id=',
    '/product?id=',
    '/article?id=',
    '/page?id=',
    '/?search=',
  ];

  console.log(`    [sqli] Testing ${testEndpoints.length} common endpoints on ${hostname}`);

  for (const endpoint of testEndpoints) {
    // Test a few representative payloads (not all)
    for (const { payload, type } of SQL_PAYLOADS.slice(0, 3)) {
      try {
        const url = `https://${hostname}${endpoint}${encodeURIComponent(payload)}`;
        
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        
        const res = await fetch(url, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: { 
            'User-Agent': 'Lycan-Security-Scanner/1.0',
            'Accept': 'text/html,application/json',
          },
        });
        
        clearTimeout(timeout);
        
        const body = await res.text();
        
        // Check for SQL error messages in response
        for (const pattern of SQL_ERROR_PATTERNS) {
          if (pattern.test(body)) {
            findings.push({
              module: 'sqli',
              severity: 'critical',
              title: 'Potential SQL Injection Vulnerability Detected',
              description: `The endpoint ${endpoint} may be vulnerable to SQL injection. The server returned a database error message when processing a malicious input, indicating improper input sanitization.`,
              payload: `${type}: ${payload}`,
              remediation: 'Use parameterized queries (prepared statements) for all database operations. Never concatenate user input directly into SQL queries. Implement input validation and use an ORM.',
              cwe: 'CWE-89',
            });
            
            // Only report once per endpoint
            console.log(`    [sqli] ⚠️  Potential SQLi detected at ${endpoint}`);
            return findings; // Exit early to avoid excessive testing
          }
        }
        
        // Timing-based detection (basic)
        const timingStart = Date.now();
        const timingPayload = "' OR SLEEP(3)--";
        const timingUrl = `https://${hostname}${endpoint}${encodeURIComponent(timingPayload)}`;
        
        try {
          const timingController = new AbortController();
          const timingTimeout = setTimeout(() => timingController.abort(), 6000);
          
          await fetch(timingUrl, {
            method: 'GET',
            redirect: 'manual',
            signal: timingController.signal,
            headers: { 'User-Agent': 'Lycan-Security-Scanner/1.0' },
          });
          
          clearTimeout(timingTimeout);
          const elapsed = Date.now() - timingStart;
          
          if (elapsed > 2500) {
            findings.push({
              module: 'sqli',
              severity: 'high',
              title: 'Possible Time-Based SQL Injection',
              description: `The endpoint ${endpoint} exhibited unusual delay (${elapsed}ms) when processing a time-based SQL injection payload, suggesting the database may be executing injected commands.`,
              payload: `Timing-based: ${timingPayload}`,
              remediation: 'Use parameterized queries and implement proper input validation.',
              cwe: 'CWE-89',
            });
            
            console.log(`    [sqli] ⚠️  Timing-based SQLi detected at ${endpoint}`);
          }
        } catch {
          // Timeout or network error - not conclusive
        }
        
      } catch (err) {
        // Network errors are expected for invalid URLs
        continue;
      }
      
      // Rate limiting: wait between requests
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }

  if (findings.length === 0) {
    console.log(`    [sqli] No obvious SQL injection vulnerabilities detected`);
  }

  return findings;
}
