"use strict";
/**
 * Sensitive Information Disclosure Detection Module
 *
 * Scans for exposed sensitive data:
 * - Backup files (.bak, .old, .backup, .zip)
 * - Configuration files (.env, config.php, web.config)
 * - Git exposure (.git/, .gitignore)
 * - Database files (.sql, .db, .sqlite)
 * - Log files (error.log, access.log)
 * - Source code files (.php~, .swp)
 * - API keys and secrets in responses
 * - Directory listings
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runInfoDisclosure = runInfoDisclosure;
const axios_1 = __importDefault(require("axios"));
const SENSITIVE_FILES = [
    // Git exposure
    '.git/HEAD',
    '.git/config',
    '.gitignore',
    // Environment files
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    'env',
    // Configuration files
    'config.php',
    'configuration.php',
    'wp-config.php',
    'web.config',
    'database.yml',
    'settings.php',
    'app.config',
    // Backup files
    'backup.zip',
    'backup.tar.gz',
    'backup.sql',
    'database.sql',
    'db.sql',
    'dump.sql',
    'site.zip',
    'www.zip',
    // Log files
    'error.log',
    'errors.log',
    'access.log',
    'debug.log',
    'app.log',
    'laravel.log',
    // Database files
    'database.db',
    'database.sqlite',
    'db.sqlite3',
    'data.db',
    // Source maps
    'bundle.js.map',
    'main.js.map',
    'app.js.map',
    // Common sensitive paths
    'phpinfo.php',
    'info.php',
    'test.php',
    'admin.php',
    'install.php',
    'setup.php',
];
const SENSITIVE_DIRECTORIES = [
    '.git/',
    '.svn/',
    '.hg/',
    'backup/',
    'backups/',
    'logs/',
    'log/',
    'temp/',
    'tmp/',
    'admin/',
    'phpmyadmin/',
    'pma/',
    '.env/',
];
// Patterns for detecting secrets in responses
const SECRET_PATTERNS = [
    { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
    { name: 'AWS Secret Key', regex: /aws_secret_access_key\s*=\s*[\w\/\+]{40}/, severity: 'critical' },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/, severity: 'critical' },
    { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36}/, severity: 'critical' },
    { name: 'Private Key', regex: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/, severity: 'critical' },
    { name: 'Stripe API Key', regex: /sk_live_[0-9a-zA-Z]{24}/, severity: 'critical' },
    { name: 'Generic API Key', regex: /api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]/, severity: 'high' },
    { name: 'Password in Code', regex: /password\s*[:=]\s*['"][^'"]{3,}['"]/, severity: 'high' },
    { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, severity: 'medium' },
];
async function runInfoDisclosure(hostname, config) {
    console.log(`[info_disclosure] Running against ${hostname}`);
    const findings = [];
    const protocol = 'https://';
    const baseUrl = `${protocol}${hostname}`;
    try {
        // 1. Test for sensitive files
        const filesToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
            ? SENSITIVE_FILES
            : SENSITIVE_FILES.slice(0, 15);
        for (const file of filesToTest) {
            const fileFindings = await testSensitiveFile(baseUrl, file);
            findings.push(...fileFindings);
        }
        // 2. Test for directory listings
        const dirFindings = await testDirectoryListings(baseUrl);
        findings.push(...dirFindings);
        // 3. Scan responses for secrets
        const secretFindings = await scanForSecrets(baseUrl);
        findings.push(...secretFindings);
        // 4. Test for backup files
        const backupFindings = await testBackupFiles(baseUrl);
        findings.push(...backupFindings);
        console.log(`[info_disclosure] Completed with ${findings.length} findings`);
    }
    catch (error) {
        console.error('[info_disclosure] Error:', error);
    }
    return findings;
}
async function testSensitiveFile(baseUrl, file) {
    const findings = [];
    try {
        const response = await axios_1.default.get(`${baseUrl}/${file}`, {
            validateStatus: () => true,
            timeout: 6000,
            maxRedirects: 0,
        });
        if (response.status === 200) {
            // Determine severity based on file type
            let severity = 'high';
            if (file.includes('.git/') || file === '.env' || file.includes('.env.')) {
                severity = 'critical';
            }
            else if (file.endsWith('.sql') || file.endsWith('.db')) {
                severity = 'critical';
            }
            else if (file.endsWith('.log') || file.endsWith('.zip')) {
                severity = 'medium';
            }
            findings.push({
                module: 'info_disclosure',
                severity,
                title: `Sensitive File Exposed: ${file}`,
                description: `The file "${file}" is publicly accessible. This file may contain sensitive information such as credentials, database dumps, source code, or configuration data.`,
                remediation: `Remove or restrict access to ${file}. Use .htaccess or server configuration to block access to sensitive files. Never commit sensitive files to version control.`,
                metadata: {
                    file,
                    url: `${baseUrl}/${file}`,
                },
            });
        }
    }
    catch (error) {
        // File doesn't exist - good!
    }
    return findings;
}
async function testDirectoryListings(baseUrl) {
    const findings = [];
    const testDirs = ['/', '/backup/', '/uploads/', '/files/', '/images/'];
    for (const dir of testDirs) {
        try {
            const response = await axios_1.default.get(`${baseUrl}${dir}`, {
                validateStatus: () => true,
                timeout: 6000,
            });
            if (response.status === 200 && typeof response.data === 'string') {
                const html = response.data;
                // Check for directory listing indicators
                const isListing = /Index of|Directory listing|Parent Directory|\[To Parent Directory\]|<title>Index/.test(html);
                if (isListing) {
                    findings.push({
                        module: 'info_disclosure',
                        severity: 'medium',
                        title: `Directory Listing Enabled: ${dir}`,
                        description: `The directory "${dir}" has directory listing enabled, exposing all files and subdirectories. Attackers can browse the directory structure and discover sensitive files.`,
                        remediation: 'Disable directory listing. For Apache: Options -Indexes. For Nginx: autoindex off. Add index.html to all directories.',
                        metadata: {
                            url: `${baseUrl}${dir}`,
                            pattern: 'directory-listing',
                        },
                    });
                }
            }
        }
        catch (error) {
            // Directory doesn't exist or access denied
        }
    }
    return findings;
}
async function scanForSecrets(baseUrl) {
    const findings = [];
    try {
        // Get homepage content
        const response = await axios_1.default.get(baseUrl, {
            validateStatus: () => true,
            timeout: 10000,
        });
        if (response.status === 200) {
            const content = typeof response.data === 'string'
                ? response.data
                : JSON.stringify(response.data);
            // Scan for each secret pattern
            for (const { name, regex, severity } of SECRET_PATTERNS) {
                const matches = content.match(regex);
                if (matches) {
                    findings.push({
                        module: 'info_disclosure',
                        severity,
                        title: `Exposed ${name} in Response`,
                        description: `A ${name} was found in the HTTP response. This credential/secret is exposed to anyone who accesses the page and should be revoked immediately.`,
                        remediation: `Revoke the exposed ${name} immediately. Never include secrets in client-side code. Use environment variables and server-side configuration. Rotate all credentials.`,
                        metadata: {
                            pattern: name,
                            url: baseUrl,
                        },
                    });
                }
            }
        }
    }
    catch (error) {
        // Failed to get content
    }
    return findings;
}
async function testBackupFiles(baseUrl) {
    const findings = [];
    // Common backup extensions to test
    const backupExtensions = ['.bak', '.old', '.backup', '.orig', '.save', '.swp', '~'];
    const testFiles = ['index.php', 'config.php', 'admin.php', 'login.php'];
    for (const file of testFiles) {
        for (const ext of backupExtensions) {
            try {
                const backupFile = `${file}${ext}`;
                const response = await axios_1.default.get(`${baseUrl}/${backupFile}`, {
                    validateStatus: () => true,
                    timeout: 5000,
                    maxRedirects: 0,
                });
                if (response.status === 200) {
                    findings.push({
                        module: 'info_disclosure',
                        severity: 'high',
                        title: `Backup File Accessible: ${backupFile}`,
                        description: `The backup file "${backupFile}" is publicly accessible. Backup files often contain source code with credentials, database connection strings, and other sensitive information.`,
                        remediation: `Remove all backup files from the web server. Never store backups in web-accessible directories. Use .gitignore to prevent committing backup files.`,
                        metadata: {
                            file: backupFile,
                            url: `${baseUrl}/${backupFile}`,
                        },
                    });
                }
            }
            catch (error) {
                // Backup doesn't exist - good!
            }
        }
    }
    return findings;
}
