"use strict";
/**
 * Lycan Security - Scanner Configuration System
 *
 * Defines scanning intensity levels based on subscription plans
 * and provides rate limiting, identification, and safety controls.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RateLimiter = exports.PLAN_CONFIGS = void 0;
exports.buildScanConfig = buildScanConfig;
exports.makeIdentifiedRequest = makeIdentifiedRequest;
// ─── Preset Configurations by Plan ──────────────────────────────────────────
exports.PLAN_CONFIGS = {
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
function buildScanConfig(scanId, targetHostname, userPlan, overrides) {
    const baseConfig = exports.PLAN_CONFIGS[userPlan];
    const userAgent = `Lycan-Security-PTaaS/2.0 (Scan-ID: ${scanId}; Plan: ${userPlan})`;
    const customHeaders = {
        'X-Lycan-Audit-ID': scanId,
        'X-Lycan-Plan': userPlan,
        'X-Lycan-Contact': 'security@lycan-security.com',
    };
    return {
        intensity: baseConfig.intensity,
        scanId,
        targetHostname,
        userPlan,
        userAgent,
        customHeaders,
        rateLimit: baseConfig.rateLimit,
        portScan: baseConfig.portScan,
        fuzzing: baseConfig.fuzzing,
        recon: baseConfig.recon,
        maxExecutionTime: baseConfig.maxExecutionTime,
        stopOnError: false,
        dryRun: false,
        ...overrides,
    };
}
// ─── Rate Limiter Class ─────────────────────────────────────────────────────
class RateLimiter {
    config;
    queue = [];
    activeRequests = 0;
    lastRequestTime = 0;
    constructor(config) {
        this.config = config;
    }
    async execute(fn) {
        // Wait for rate limit
        await this.waitForSlot();
        this.activeRequests++;
        try {
            const result = await fn();
            return result;
        }
        finally {
            this.activeRequests--;
            this.lastRequestTime = Date.now();
        }
    }
    async waitForSlot() {
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
exports.RateLimiter = RateLimiter;
// ─── HTTP Client with Identification ────────────────────────────────────────
async function makeIdentifiedRequest(url, config, options = {}) {
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
