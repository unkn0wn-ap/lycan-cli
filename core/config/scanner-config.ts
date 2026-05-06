/**
 * Lycan Security - Scanner Configuration System
 * 
 * Defines scanning intensity levels based on subscription plans
 * and provides rate limiting, identification, and safety controls.
 */

export type ScanIntensity = 'passive' | 'active' | 'aggressive';
export type PortRange = 'top100' | 'top1000' | 'full65k';
export type PayloadDepth = 'basic' | 'comprehensive' | 'exhaustive';

export interface RateLimitConfig {
  requestsPerSecond: number;
  maxConcurrentRequests: number;
  delayBetweenRequests: number; // milliseconds
  respectRobotsTxt: boolean;
}

export interface PortScanConfig {
  range: PortRange;
  tcpConnect: boolean;
  udpScan: boolean;
  serviceFingerprint: boolean;
  versionDetection: boolean;
}

export interface FuzzingConfig {
  enabled: boolean;
  payloadDepth: PayloadDepth;
  blindSqli: boolean;
  timingAnalysis: boolean;
  encodingVariations: boolean;
}

export interface ReconConfig {
  subdomainEnumeration: boolean;
  technologyFingerprinting: boolean;
  cdnWafDetection: boolean;
  informationDisclosure: boolean;
  externalDataSources: boolean; // APIs like crt.sh, Shodan
  maxSubdomains: number;
}

export interface ScanConfiguration {
  intensity: ScanIntensity;
  scanId: string;
  targetHostname: string;
  userPlan: 'free' | 'basic' | 'red_team' | 'enterprise';
  
  // Identification
  userAgent: string;
  customHeaders: Record<string, string>;
  
  // Rate limiting
  rateLimit: RateLimitConfig;
  
  // Module-specific configs
  portScan: PortScanConfig;
  fuzzing: FuzzingConfig;
  recon: ReconConfig;
  
  // Safety controls
  maxExecutionTime: number; // minutes
  stopOnError: boolean;
  dryRun: boolean; // Test mode without actual scanning
}

// ─── Preset Configurations by Plan ──────────────────────────────────────────

export const PLAN_CONFIGS: Record<string, Partial<ScanConfiguration>> = {
  free: {
    intensity: 'passive',
    rateLimit: {
      requestsPerSecond: 2,
      maxConcurrentRequests: 2,
      delayBetweenRequests: 500,
      respectRobotsTxt: true,
    },
    portScan: {
      range: 'top100',
      tcpConnect: true,
      udpScan: false,
      serviceFingerprint: false,
      versionDetection: false,
    },
    fuzzing: {
      enabled: false,
      payloadDepth: 'basic',
      blindSqli: false,
      timingAnalysis: false,
      encodingVariations: false,
    },
    recon: {
      subdomainEnumeration: false,
      technologyFingerprinting: true,
      cdnWafDetection: true,
      informationDisclosure: false,
      externalDataSources: false,
      maxSubdomains: 5,
    },
    maxExecutionTime: 5,
  },
  
  basic: {
    intensity: 'active',
    rateLimit: {
      requestsPerSecond: 5,
      maxConcurrentRequests: 5,
      delayBetweenRequests: 200,
      respectRobotsTxt: true,
    },
    portScan: {
      range: 'top1000',
      tcpConnect: true,
      udpScan: false,
      serviceFingerprint: true,
      versionDetection: true,
    },
    fuzzing: {
      enabled: true,
      payloadDepth: 'comprehensive',
      blindSqli: false,
      timingAnalysis: false,
      encodingVariations: true,
    },
    recon: {
      subdomainEnumeration: true,
      technologyFingerprinting: true,
      cdnWafDetection: true,
      informationDisclosure: true,
      externalDataSources: true,
      maxSubdomains: 20,
    },
    maxExecutionTime: 15,
  },
  
  red_team: {
    intensity: 'aggressive',
    rateLimit: {
      requestsPerSecond: 10,
      maxConcurrentRequests: 10,
      delayBetweenRequests: 100,
      respectRobotsTxt: false, // Red team ignores robots.txt
    },
    portScan: {
      range: 'full65k',
      tcpConnect: true,
      udpScan: true,
      serviceFingerprint: true,
      versionDetection: true,
    },
    fuzzing: {
      enabled: true,
      payloadDepth: 'exhaustive',
      blindSqli: true,
      timingAnalysis: true,
      encodingVariations: true,
    },
    recon: {
      subdomainEnumeration: true,
      technologyFingerprinting: true,
      cdnWafDetection: true,
      informationDisclosure: true,
      externalDataSources: true,
      maxSubdomains: 100,
    },
    maxExecutionTime: 60,
  },
  
  enterprise: {
    intensity: 'aggressive',
    rateLimit: {
      requestsPerSecond: 20,
      maxConcurrentRequests: 20,
      delayBetweenRequests: 50,
      respectRobotsTxt: false,
    },
    portScan: {
      range: 'full65k',
      tcpConnect: true,
      udpScan: true,
      serviceFingerprint: true,
      versionDetection: true,
    },
    fuzzing: {
      enabled: true,
      payloadDepth: 'exhaustive',
      blindSqli: true,
      timingAnalysis: true,
      encodingVariations: true,
    },
    recon: {
      subdomainEnumeration: true,
      technologyFingerprinting: true,
      cdnWafDetection: true,
      informationDisclosure: true,
      externalDataSources: true,
      maxSubdomains: 500,
    },
    maxExecutionTime: 120,
  },
};

// ─── Configuration Builder ──────────────────────────────────────────────────

export function buildScanConfig(
  scanId: string,
  targetHostname: string,
  userPlan: 'free' | 'basic' | 'red_team' | 'enterprise',
  overrides?: Partial<ScanConfiguration>
): ScanConfiguration {
  const baseConfig = PLAN_CONFIGS[userPlan];
  
  const userAgent = `Lycan-Security-PTaaS/2.0 (Scan-ID: ${scanId}; Plan: ${userPlan})`;
  const customHeaders = {
    'X-Lycan-Audit-ID': scanId,
    'X-Lycan-Plan': userPlan,
    'X-Lycan-Contact': 'security@lycan-security.com',
  };
  
  return {
    intensity: baseConfig.intensity!,
    scanId,
    targetHostname,
    userPlan,
    userAgent,
    customHeaders,
    rateLimit: baseConfig.rateLimit!,
    portScan: baseConfig.portScan!,
    fuzzing: baseConfig.fuzzing!,
    recon: baseConfig.recon!,
    maxExecutionTime: baseConfig.maxExecutionTime!,
    stopOnError: false,
    dryRun: false,
    ...overrides,
  };
}

// ─── Rate Limiter Class ─────────────────────────────────────────────────────

export class RateLimiter {
  private queue: Array<() => Promise<void>> = [];
  private activeRequests = 0;
  private lastRequestTime = 0;
  
  constructor(private config: RateLimitConfig) {}
  
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    // Wait for rate limit
    await this.waitForSlot();
    
    this.activeRequests++;
    
    try {
      const result = await fn();
      return result;
    } finally {
      this.activeRequests--;
      this.lastRequestTime = Date.now();
    }
  }
  
  private async waitForSlot(): Promise<void> {
    // Check concurrent requests limit
    while (this.activeRequests >= this.config.maxConcurrentRequests) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    
    // Check requests per second limit
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    const minDelay = this.config.delayBetweenRequests;
    
    if (timeSinceLastRequest < minDelay) {
      await new Promise(resolve => setTimeout(resolve, minDelay - timeSinceLastRequest));
    }
  }
  
  getStats() {
    return {
      activeRequests: this.activeRequests,
      queueLength: this.queue.length,
    };
  }
}

// ─── HTTP Client with Identification ────────────────────────────────────────

export async function makeIdentifiedRequest(
  url: string,
  config: ScanConfiguration,
  options: RequestInit = {}
): Promise<Response> {
  const headers = {
    'User-Agent': config.userAgent,
    ...config.customHeaders,
    ...options.headers,
  };
  
  return fetch(url, {
    ...options,
    headers,
  });
}
