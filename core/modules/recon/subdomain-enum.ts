import axios from 'axios';
import { lookup } from 'dns/promises';
import type { ScanConfiguration } from '../../config/scanner-config';

interface SubdomainResult {
  subdomains: Array<{
    subdomain: string;
    ip?: string;
    active: boolean;
    source: 'crt.sh' | 'dns_bruteforce';
  }>;
  findings: Array<{
    type: 'subdomain_found' | 'sensitive_subdomain';
    severity: 'info' | 'low' | 'medium';
    title: string;
    description: string;
  }>;
}

const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'staging', 
  'test', 'portal', 'vpn', 'webmail', 'smtp', 'pop', 'imap',
  'm', 'mobile', 'app', 'cdn', 'static', 'assets', 'img', 'images',
  'shop', 'store', 'secure', 'login', 'dashboard', 'panel',
  'cpanel', 'whm', 'ns1', 'ns2', 'mx', 'mx1', 'mx2'
];

const SENSITIVE_SUBDOMAIN_PATTERNS = [
  /^dev\./i, /^development\./i, /^staging\./i, /^test\./i,
  /^admin\./i, /^panel\./i, /^cpanel\./i, /^internal\./i,
  /^vpn\./i, /^backup\./i, /^old\./i, /^legacy\./i
];

export async function enumerateSubdomains(
  domain: string,
  config: ScanConfiguration
): Promise<SubdomainResult> {
  const result: SubdomainResult = {
    subdomains: [],
    findings: []
  };

  const foundSubdomains = new Set<string>();

  try {
    // Method 1: Certificate Transparency Logs (crt.sh)
    if (config.intensity === 'active' || config.intensity === 'aggressive') {
      try {
        const crtResponse = await axios.get(
          `https://crt.sh/?q=%.${domain}&output=json`,
          {
            timeout: 15000,
            validateStatus: (status) => status === 200,
            headers: {
              'User-Agent': config.userAgent,
              'Accept': 'application/json'
            }
          }
        );

        if (crtResponse.status === 200 && Array.isArray(crtResponse.data)) {
          let ctLogCount = 0;
          for (const entry of crtResponse.data) {
            const nameValue = entry.name_value;
            const subdomains = nameValue.split('\n');
            
            for (const subdomain of subdomains) {
              const cleaned = subdomain.trim().toLowerCase();
              if (cleaned.endsWith(domain) && !cleaned.includes('*')) {
                foundSubdomains.add(cleaned);
                ctLogCount++;
              }
            }
          }
          console.log(`    [recon] Certificate Transparency: found ${ctLogCount} subdomains`);
        }
      } catch (error: any) {
        // crt.sh can be flaky or rate-limited, this is not critical
        console.log(`    [recon] Certificate Transparency lookup failed (${error?.response?.status || 'network error'}), falling back to DNS bruteforce only`);
      }
    }

    // Method 2: DNS Bruteforce (limited by plan)
    const maxBruteforce = config.intensity === 'passive' ? 0 :
                          config.intensity === 'active' ? 20 : 40;

    if (maxBruteforce > 0) {
      const subdomainsToTry = COMMON_SUBDOMAINS.slice(0, maxBruteforce);

      for (const sub of subdomainsToTry) {
        const fullDomain = `${sub}.${domain}`;
        
        try {
          const addresses = await lookup(fullDomain, { all: true });
          if (addresses.length > 0) {
            foundSubdomains.add(fullDomain);
            
            result.subdomains.push({
              subdomain: fullDomain,
              ip: addresses[0].address,
              active: true,
              source: 'dns_bruteforce'
            });
          }
        } catch (error) {
          // Subdomain does not resolve
        }

        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    // Process all found subdomains from CT logs
    for (const subdomain of foundSubdomains) {
      if (!result.subdomains.find(s => s.subdomain === subdomain)) {
        let ip: string | undefined;
        let active = false;

        try {
          const addresses = await lookup(subdomain, { all: true });
          if (addresses.length > 0) {
            ip = addresses[0].address;
            active = true;
          }
        } catch (error) {
          // Subdomain not active
        }

        result.subdomains.push({
          subdomain,
          ip,
          active,
          source: 'crt.sh'
        });

        // Check if sensitive subdomain
        for (const pattern of SENSITIVE_SUBDOMAIN_PATTERNS) {
          if (pattern.test(subdomain) && active) {
            result.findings.push({
              type: 'sensitive_subdomain',
              severity: 'medium',
              title: `Sensitive subdomain found: ${subdomain}`,
              description: `Potentially sensitive subdomain is publicly accessible: ${subdomain} (${ip})`
            });
          }
        }

        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    if (result.subdomains.length > 0) {
      const activeCount = result.subdomains.filter(s => s.active).length;
      console.log(`    [recon] Subdomain enumeration complete: ${activeCount} active / ${result.subdomains.length} total`);
      
      result.findings.push({
        type: 'subdomain_found',
        severity: 'info',
        title: `Found ${result.subdomains.length} subdomains`,
        description: `Enumerated ${activeCount} active subdomains (${result.subdomains.filter(s => s.source === 'crt.sh').length} from CT logs, ${result.subdomains.filter(s => s.source === 'dns_bruteforce').length} from DNS)`
      });
    } else {
      console.log(`    [recon] No subdomains found for ${domain}`);
    }

  } catch (error) {
    console.error(`    [recon] Subdomain enumeration critical error for ${domain}:`, error);
  }

  return result;
}
