"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.performFingerprinting = performFingerprinting;
const axios_1 = __importDefault(require("axios"));
const SERVER_SIGNATURES = {
    'nginx': { patterns: [/nginx\/([\d.]+)/i], category: 'server' },
    'apache': { patterns: [/apache\/([\d.]+)/i], category: 'server' },
    'iis': { patterns: [/microsoft-iis\/([\d.]+)/i], category: 'server' },
    'cloudflare': { patterns: [/cloudflare/i], category: 'server' }
};
const FRAMEWORK_SIGNATURES = {
    'next.js': {
        patterns: [/__NEXT_DATA__/, /\/_next\/static\//],
        headers: ['x-nextjs-cache'],
        category: 'framework'
    },
    'react': {
        patterns: [/react/i, /__REACT/],
        headers: [],
        category: 'framework'
    },
    'angular': {
        patterns: [/ng-version/, /angular/i],
        headers: [],
        category: 'framework'
    },
    'vue.js': {
        patterns: [/vue\.js/, /__VUE__/],
        headers: [],
        category: 'framework'
    },
    'express': {
        headers: ['x-powered-by'],
        patterns: [/express/i],
        category: 'framework'
    },
    'laravel': {
        headers: ['x-powered-by'],
        patterns: [/laravel/i],
        category: 'framework'
    },
    'django': {
        headers: ['x-frame-options'],
        patterns: [/django/i, /csrftoken/],
        category: 'framework'
    },
    'asp.net': {
        headers: ['x-aspnet-version', 'x-aspnetmvc-version'],
        patterns: [/__VIEWSTATE/, /asp\.net/i],
        category: 'framework'
    }
};
const CMS_SIGNATURES = {
    'wordpress': {
        patterns: [/wp-content/, /wp-includes/, /wordpress/i],
        paths: ['/wp-admin/', '/wp-login.php'],
        headers: [],
        category: 'cms'
    },
    'drupal': {
        patterns: [/drupal/i, /sites\/default/],
        headers: ['x-drupal-cache'],
        paths: [],
        category: 'cms'
    },
    'joomla': {
        patterns: [/joomla/i, /\/components\/com_/],
        headers: [],
        paths: [],
        category: 'cms'
    },
    'shopify': {
        patterns: [/shopify/i, /cdn\.shopify\.com/],
        headers: ['x-shopid'],
        paths: [],
        category: 'cms'
    },
    'magento': {
        patterns: [/magento/i, /\/mage\//],
        headers: [],
        paths: [],
        category: 'cms'
    }
};
async function performFingerprinting(url, config) {
    const technologies = [];
    const findings = [];
    try {
        const response = await axios_1.default.get(url, {
            timeout: 10000,
            maxRedirects: 5,
            validateStatus: () => true,
            headers: {
                'User-Agent': config.userAgent
            }
        });
        const headers = response.headers;
        const body = response.data;
        // Detect web server
        if (headers['server']) {
            for (const [name, sig] of Object.entries(SERVER_SIGNATURES)) {
                for (const pattern of sig.patterns) {
                    const match = headers['server'].match(pattern);
                    if (match) {
                        technologies.push({
                            name: name,
                            category: sig.category,
                            version: match[1],
                            confidence: 100
                        });
                        findings.push({
                            type: 'version_disclosure',
                            severity: 'low',
                            title: `Server version disclosure: ${name}`,
                            description: `Server header reveals ${name} version ${match[1] || 'unknown'}`,
                            cwe: 'CWE-200'
                        });
                    }
                }
            }
        }
        // Detect frameworks
        for (const [name, sig] of Object.entries(FRAMEWORK_SIGNATURES)) {
            let detected = false;
            let version;
            if (sig.headers) {
                for (const header of sig.headers) {
                    if (headers[header]) {
                        detected = true;
                        const versionMatch = headers[header].match(/([\d.]+)/);
                        if (versionMatch) {
                            version = versionMatch[1];
                        }
                    }
                }
            }
            if (sig.patterns) {
                for (const pattern of sig.patterns) {
                    if (pattern.test(body)) {
                        detected = true;
                    }
                }
            }
            if (detected) {
                technologies.push({
                    name: name,
                    category: sig.category,
                    version,
                    confidence: 90
                });
            }
        }
        // Detect CMS
        for (const [name, sig] of Object.entries(CMS_SIGNATURES)) {
            let detected = false;
            if (sig.patterns) {
                for (const pattern of sig.patterns) {
                    if (pattern.test(body)) {
                        detected = true;
                        break;
                    }
                }
            }
            if (sig.headers) {
                for (const header of sig.headers) {
                    if (headers[header]) {
                        detected = true;
                    }
                }
            }
            if (detected) {
                technologies.push({
                    name: name,
                    category: sig.category,
                    confidence: 85
                });
                findings.push({
                    type: 'version_disclosure',
                    severity: 'info',
                    title: `CMS detected: ${name}`,
                    description: `Target is using ${name} content management system`,
                    cwe: 'CWE-200'
                });
            }
        }
        // Detect programming language from headers
        if (headers['x-powered-by']) {
            const poweredBy = headers['x-powered-by'];
            const phpMatch = poweredBy.match(/PHP\/([\d.]+)/i);
            if (phpMatch) {
                technologies.push({
                    name: 'PHP',
                    category: 'language',
                    version: phpMatch[1],
                    confidence: 100
                });
            }
        }
    }
    catch (error) {
        console.error(`Fingerprinting error for ${url}:`, error);
    }
    return { technologies, findings };
}
