/**
 * Advanced Cookie Security Analysis Module
 * 
 * Deep analysis of cookie security:
 * - Missing Secure flag
 * - Missing HttpOnly flag
 * - Missing SameSite attribute
 * - Cookie prefix (__Secure-, __Host-)
 * - Sensitive data in cookies
 * - Cookie scope (Domain, Path)
 * - Session cookie attributes
 * - Cookie encryption/signing
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
    cookie?: string;
    attribute?: string;
    value?: string;
    [key: string]: unknown;
  };
}

interface CookieAttributes {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | null;
  domain: string | null;
  path: string | null;
  maxAge: number | null;
  expires: Date | null;
}

const SENSITIVE_COOKIE_NAMES = [
  'session',
  'token',
  'auth',
  'jwt',
  'access_token',
  'refresh_token',
  'api_key',
  'password',
  'secret',
  'credential',
];

export async function runAdvancedCookies(
  hostname: string,
  config: ScanConfiguration
): Promise<Finding[]> {
  console.log(`[cookies] Running against ${hostname}`);
  const findings: Finding[] = [];
  const protocol = 'https://';
  const baseUrl = `${protocol}${hostname}`;

  try {
    const response = await axios.get(baseUrl, {
      maxRedirects: 5,
      validateStatus: () => true,
      timeout: 10000,
    });

    const setCookieHeaders = response.headers['set-cookie'] || [];
    
    if (setCookieHeaders.length === 0) {
      findings.push({
        module: 'cookies',
        severity: 'info',
        title: 'No Cookies Set',
        description: 'The application does not set any cookies. If this is a stateful application, ensure session management is implemented correctly.',
        metadata: {
          cookie: 'none',
        },
      });
      return findings;
    }

    // Parse and analyze each cookie
    for (const cookieHeader of setCookieHeaders) {
      const cookie = parseCookie(cookieHeader);
      
      // Check for missing security flags
      findings.push(...checkSecurityFlags(cookie));
      
      // Check for sensitive data exposure
      findings.push(...checkSensitiveData(cookie));
      
      // Check cookie prefixes
      findings.push(...checkCookiePrefixes(cookie));
      
      // Check cookie scope
      findings.push(...checkCookieScope(cookie, hostname));
      
      // Check session cookie attributes
      findings.push(...checkSessionCookie(cookie));
    }

    console.log(`[cookies] Completed with ${findings.length} findings`);
  } catch (error) {
    console.error('[cookies] Error:', error);
  }

  return findings;
}

function parseCookie(cookieHeader: string): CookieAttributes {
  const parts = cookieHeader.split(';').map(p => p.trim());
  const [nameValue, ...attributes] = parts;
  const [name, value] = nameValue.split('=');

  const cookie: CookieAttributes = {
    name: name || '',
    value: value || '',
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    maxAge: null,
    expires: null,
  };

  for (const attr of attributes) {
    const [key, val] = attr.split('=').map(s => s.trim());
    const lowerKey = key.toLowerCase();

    if (lowerKey === 'secure') {
      cookie.secure = true;
    } else if (lowerKey === 'httponly') {
      cookie.httpOnly = true;
    } else if (lowerKey === 'samesite') {
      cookie.sameSite = (val as 'Strict' | 'Lax' | 'None') || 'Lax';
    } else if (lowerKey === 'domain') {
      cookie.domain = val;
    } else if (lowerKey === 'path') {
      cookie.path = val;
    } else if (lowerKey === 'max-age') {
      cookie.maxAge = parseInt(val) || null;
    } else if (lowerKey === 'expires') {
      cookie.expires = new Date(val);
    }
  }

  return cookie;
}

function checkSecurityFlags(cookie: CookieAttributes): Finding[] {
  const findings: Finding[] = [];
  
  // Check Secure flag
  if (!cookie.secure) {
    const isSensitive = SENSITIVE_COOKIE_NAMES.some(name => 
      cookie.name.toLowerCase().includes(name)
    );
    
    const severity = isSensitive ? 'high' : 'medium';
    
    findings.push({
      module: 'cookies',
      severity,
      title: `Cookie Without Secure Flag: ${cookie.name}`,
      description: `The cookie "${cookie.name}" does not have the Secure flag. This allows the cookie to be transmitted over unencrypted HTTP connections, exposing it to interception.`,
      remediation: 'Add the Secure flag to all cookies, especially session/auth cookies. Example: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict',
      metadata: {
        cookie: cookie.name,
        attribute: 'Secure',
        value: 'missing',
      },
    });
  }
  
  // Check HttpOnly flag
  if (!cookie.httpOnly) {
    const isSensitive = SENSITIVE_COOKIE_NAMES.some(name => 
      cookie.name.toLowerCase().includes(name)
    );
    
    if (isSensitive) {
      findings.push({
        module: 'cookies',
        severity: 'high',
        title: `Session Cookie Without HttpOnly: ${cookie.name}`,
        description: `The cookie "${cookie.name}" appears to be a session/auth cookie but lacks the HttpOnly flag. JavaScript code can access this cookie, making it vulnerable to XSS attacks.`,
        remediation: 'Add HttpOnly flag to prevent JavaScript access: Set-Cookie: name=value; HttpOnly; Secure; SameSite=Strict',
        metadata: {
          cookie: cookie.name,
          attribute: 'HttpOnly',
          value: 'missing',
        },
      });
    } else {
      findings.push({
        module: 'cookies',
        severity: 'low',
        title: `Cookie Without HttpOnly: ${cookie.name}`,
        description: `The cookie "${cookie.name}" can be accessed by JavaScript, increasing XSS risk.`,
        remediation: 'Add HttpOnly flag unless JavaScript access is required.',
        metadata: {
          cookie: cookie.name,
          attribute: 'HttpOnly',
          value: 'missing',
        },
      });
    }
  }
  
  // Check SameSite attribute
  if (!cookie.sameSite) {
    const isSensitive = SENSITIVE_COOKIE_NAMES.some(name => 
      cookie.name.toLowerCase().includes(name)
    );
    
    const severity = isSensitive ? 'high' : 'medium';
    
    findings.push({
      module: 'cookies',
      severity,
      title: `Cookie Without SameSite: ${cookie.name}`,
      description: `The cookie "${cookie.name}" does not have a SameSite attribute, making it vulnerable to CSRF attacks.`,
      remediation: 'Add SameSite=Strict or SameSite=Lax to prevent CSRF: Set-Cookie: name=value; SameSite=Strict; Secure; HttpOnly',
      metadata: {
        cookie: cookie.name,
        attribute: 'SameSite',
        value: 'missing',
      },
    });
  } else if (cookie.sameSite === 'None' && !cookie.secure) {
    findings.push({
      module: 'cookies',
      severity: 'high',
      title: `SameSite=None Without Secure: ${cookie.name}`,
      description: `The cookie "${cookie.name}" uses SameSite=None without the Secure flag. This is invalid and browsers will reject it.`,
      remediation: 'Cookies with SameSite=None must also have Secure flag.',
      metadata: {
        cookie: cookie.name,
        attribute: 'SameSite',
        value: 'None-without-Secure',
      },
    });
  }
  
  return findings;
}

function checkSensitiveData(cookie: CookieAttributes): Finding[] {
  const findings: Finding[] = [];
  
  // Check if cookie value looks like sensitive data (not hashed/encrypted)
  const value = cookie.value;
  
  // Check for plaintext patterns
  if (value && value.length < 100) {
    // Check for email
    if (/@/.test(value)) {
      findings.push({
        module: 'cookies',
        severity: 'medium',
        title: `Potential Email in Cookie: ${cookie.name}`,
        description: `The cookie "${cookie.name}" appears to contain an email address. Sensitive data should not be stored in plaintext cookies.`,
        remediation: 'Do not store sensitive data in cookies. Use server-side sessions instead.',
        metadata: {
          cookie: cookie.name,
          pattern: 'email',
        },
      });
    }
    
    // Check for simple numeric user IDs (predictable)
    if (/^\d+$/.test(value) && value.length < 10) {
      findings.push({
        module: 'cookies',
        severity: 'medium',
        title: `Predictable Cookie Value: ${cookie.name}`,
        description: `The cookie "${cookie.name}" contains a simple numeric value (${value}). Predictable cookie values can be exploited for session hijacking.`,
        remediation: 'Use cryptographically secure random values for session cookies. Use UUIDs or signed tokens.',
        metadata: {
          cookie: cookie.name,
          pattern: 'numeric-id',
        },
      });
    }
  }
  
  return findings;
}

function checkCookiePrefixes(cookie: CookieAttributes): Finding[] {
  const findings: Finding[] = [];
  
  // Check for __Secure- prefix
  if (cookie.name.startsWith('__Secure-')) {
    if (!cookie.secure) {
      findings.push({
        module: 'cookies',
        severity: 'high',
        title: `__Secure- Prefix Without Secure Flag: ${cookie.name}`,
        description: `Cookies with __Secure- prefix must have the Secure flag, but "${cookie.name}" does not. Browsers will reject this cookie.`,
        remediation: 'Add Secure flag to cookies with __Secure- prefix.',
        metadata: {
          cookie: cookie.name,
          prefix: '__Secure-',
        },
      });
    }
  }
  
  // Check for __Host- prefix
  if (cookie.name.startsWith('__Host-')) {
    if (!cookie.secure) {
      findings.push({
        module: 'cookies',
        severity: 'high',
        title: `__Host- Prefix Requirements Violated: ${cookie.name}`,
        description: `Cookies with __Host- prefix must have Secure flag, no Domain attribute, and Path=/. "${cookie.name}" does not meet these requirements.`,
        remediation: 'Ensure __Host- cookies have: Secure flag, Path=/, and no Domain attribute.',
        metadata: {
          cookie: cookie.name,
          prefix: '__Host-',
        },
      });
    }
    
    if (cookie.domain) {
      findings.push({
        module: 'cookies',
        severity: 'medium',
        title: `__Host- Cookie Has Domain Attribute: ${cookie.name}`,
        description: `Cookies with __Host- prefix cannot have a Domain attribute.`,
        remediation: 'Remove Domain attribute from __Host- prefixed cookies.',
        metadata: {
          cookie: cookie.name,
        },
      });
    }
    
    if (cookie.path !== '/') {
      findings.push({
        module: 'cookies',
        severity: 'medium',
        title: `__Host- Cookie Path Not Root: ${cookie.name}`,
        description: `Cookies with __Host- prefix must have Path=/.`,
        remediation: 'Set Path=/ for __Host- prefixed cookies.',
        metadata: {
          cookie: cookie.name,
        },
      });
    }
  }
  
  return findings;
}

function checkCookieScope(cookie: CookieAttributes, hostname: string): Finding[] {
  const findings: Finding[] = [];
  
  // Check for overly broad domain scope
  if (cookie.domain) {
    const domain = cookie.domain.toLowerCase();
    
    // Check for leading dot (makes cookie available to all subdomains)
    if (domain.startsWith('.')) {
      findings.push({
        module: 'cookies',
        severity: 'low',
        title: `Cookie Available to All Subdomains: ${cookie.name}`,
        description: `The cookie "${cookie.name}" has Domain=${cookie.domain}, making it accessible to all subdomains. This increases attack surface.`,
        remediation: 'Restrict cookie scope to specific subdomain if possible. Omit Domain attribute to limit to current host only.',
        metadata: {
          cookie: cookie.name,
          domain: cookie.domain,
        },
      });
    }
  }
  
  // Check for overly broad path scope
  if (cookie.path === '/') {
    const isSensitive = SENSITIVE_COOKIE_NAMES.some(name => 
      cookie.name.toLowerCase().includes(name)
    );
    
    if (isSensitive) {
      findings.push({
        module: 'cookies',
        severity: 'info',
        title: `Session Cookie Available to All Paths: ${cookie.name}`,
        description: `The cookie "${cookie.name}" has Path=/, making it accessible to all paths on the domain. Consider restricting to specific paths if possible.`,
        remediation: 'Set Path to the most specific path needed (e.g., Path=/app).',
        metadata: {
          cookie: cookie.name,
          path: cookie.path,
        },
      });
    }
  }
  
  return findings;
}

function checkSessionCookie(cookie: CookieAttributes): Finding[] {
  const findings: Finding[] = [];
  
  const isSensitive = SENSITIVE_COOKIE_NAMES.some(name => 
    cookie.name.toLowerCase().includes(name)
  );
  
  if (isSensitive) {
    // Check for session cookie without expiration
    if (!cookie.maxAge && !cookie.expires) {
      // This is a session cookie (deleted when browser closes)
      findings.push({
        module: 'cookies',
        severity: 'info',
        title: `Session Cookie Without Expiration: ${cookie.name}`,
        description: `The cookie "${cookie.name}" is a session cookie (no Max-Age or Expires). It will be deleted when the browser closes. This is secure for sensitive cookies.`,
        remediation: 'Session cookies are appropriate for authentication. No action needed unless you want persistent sessions.',
        metadata: {
          cookie: cookie.name,
          type: 'session',
        },
      });
    } else {
      // Persistent auth cookie
      const maxAge = cookie.maxAge || (cookie.expires ? Math.floor((cookie.expires.getTime() - Date.now()) / 1000) : 0);
      
      if (maxAge > 86400 * 30) { // > 30 days
        findings.push({
          module: 'cookies',
          severity: 'medium',
          title: `Long-lived Authentication Cookie: ${cookie.name}`,
          description: `The cookie "${cookie.name}" has a long lifetime (${Math.floor(maxAge / 86400)} days). Long-lived auth cookies increase security risk if stolen.`,
          remediation: 'Consider shorter session lifetimes (e.g., 1-7 days) with refresh tokens for extended access.',
          metadata: {
            cookie: cookie.name,
            maxAge: maxAge,
          },
        });
      }
    }
  }
  
  return findings;
}
