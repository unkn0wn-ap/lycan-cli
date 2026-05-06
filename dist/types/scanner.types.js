"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getConfigForPlan = getConfigForPlan;
function getConfigForPlan(userPlan, scanId) {
    const baseConfig = {
        intensity: 'passive',
        userPlan,
        userAgent: `Lycan-Security-PTaaS/2.0 (Scan-ID: ${scanId})`,
        requestTimeout: 10000,
        rateLimit: {
            requestsPerSecond: 1,
            maxConcurrent: 2,
            delayBetweenRequests: 1000
        }
    };
    switch (userPlan) {
        case 'free':
            return {
                ...baseConfig,
                intensity: 'passive',
                rateLimit: {
                    requestsPerSecond: 1,
                    maxConcurrent: 2,
                    delayBetweenRequests: 2000
                },
                portScan: {
                    enabled: false,
                    range: 'top100',
                    tcpConnect: false,
                    udpScan: false,
                    serviceFingerprint: false
                },
                fuzzing: {
                    enabled: false,
                    payloadDepth: 'basic',
                    blindSqli: false,
                    timingAnalysis: false
                }
            };
        case 'basic':
            return {
                ...baseConfig,
                intensity: 'active',
                rateLimit: {
                    requestsPerSecond: 3,
                    maxConcurrent: 5,
                    delayBetweenRequests: 500
                },
                portScan: {
                    enabled: true,
                    range: 'top1000',
                    tcpConnect: true,
                    udpScan: false,
                    serviceFingerprint: true
                },
                fuzzing: {
                    enabled: true,
                    payloadDepth: 'comprehensive',
                    blindSqli: false,
                    timingAnalysis: false
                }
            };
        case 'red_team':
        case 'enterprise':
            return {
                ...baseConfig,
                intensity: 'aggressive',
                rateLimit: {
                    requestsPerSecond: 10,
                    maxConcurrent: 10,
                    delayBetweenRequests: 200
                },
                portScan: {
                    enabled: true,
                    range: 'full65k',
                    tcpConnect: true,
                    udpScan: true,
                    serviceFingerprint: true
                },
                fuzzing: {
                    enabled: true,
                    payloadDepth: 'exhaustive',
                    blindSqli: true,
                    timingAnalysis: true
                }
            };
        default:
            return baseConfig;
    }
}
