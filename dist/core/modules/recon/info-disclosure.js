"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.checkInfoDisclosure = checkInfoDisclosure;
const axios_1 = __importDefault(require("axios"));
const SENSITIVE_FILES = [
    // Environment and config files
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.development',
    '/config.php',
    '/wp-config.php',
    '/configuration.php',
    '/config.json',
    '/config.yml',
    '/config.yaml',
    '/settings.py',
    '/settings.php',
    // Version control
    '/.git/config',
    '/.git/HEAD',
    '/.gitignore',
    '/.svn/entries',
    // Backup files
    '/backup.sql',
    '/backup.tar.gz',
    '/backup.zip',
    '/database.sql',
    '/db.sql',
    '/dump.sql',
    '/site-backup.tar.gz',
    // Common sensitive files
    '/robots.txt',
    '/sitemap.xml',
    '/phpinfo.php',
    '/.htaccess',
    '/.htpasswd',
    '/web.config',
    '/composer.json',
    '/package.json',
    '/package-lock.json',
    '/.DS_Store',
    // Admin/debug panels
    '/admin',
    '/administrator',
    '/wp-admin',
    '/phpmyadmin',
    '/debug',
    '/.vscode/settings.json'
];
async function checkInfoDisclosure(url, config) {
    const result = {
        exposedFiles: [],
        findings: []
    };
    try {
        const urlObj = new URL(url);
        const baseUrl = `${urlObj.protocol}//${urlObj.host}`;
        // Check robots.txt first (always safe to check)
        try {
            const robotsResponse = await axios_1.default.get(`${baseUrl}/robots.txt`, {
                timeout: 10000,
                validateStatus: () => true,
                headers: {
                    'User-Agent': config.userAgent
                }
            });
            if (robotsResponse.status === 200) {
                const robotsContent = robotsResponse.data;
                result.exposedFiles.push({
                    path: '/robots.txt',
                    type: 'sensitive_file',
                    accessible: true
                });
                // Parse robots.txt for disallowed paths
                const disallowedPaths = robotsContent
                    .split('\n')
                    .filter((line) => line.toLowerCase().startsWith('disallow:'))
                    .map((line) => line.split(':')[1].trim())
                    .filter((path) => path && path !== '/');
                if (disallowedPaths.length > 0) {
                    result.findings.push({
                        type: 'information_disclosure',
                        severity: 'low',
                        title: 'robots.txt reveals hidden paths',
                        description: `robots.txt exposes ${disallowedPaths.length} potentially sensitive paths: ${disallowedPaths.slice(0, 5).join(', ')}`,
                        cwe: 'CWE-200'
                    });
                }
            }
        }
        catch (error) {
            // robots.txt not accessible
        }
        // Check for sensitive file exposure
        const filesToCheck = config.intensity === 'passive' ?
            SENSITIVE_FILES.slice(0, 10) :
            config.intensity === 'active' ?
                SENSITIVE_FILES.slice(0, 25) :
                SENSITIVE_FILES;
        for (const path of filesToCheck) {
            try {
                const response = await axios_1.default.get(`${baseUrl}${path}`, {
                    timeout: 5000,
                    validateStatus: () => true,
                    maxRedirects: 0,
                    headers: {
                        'User-Agent': config.userAgent
                    }
                });
                const accessible = response.status === 200;
                if (accessible) {
                    let fileType = 'sensitive_file';
                    let severity = 'medium';
                    if (path.includes('.git') || path.includes('.svn')) {
                        fileType = 'vcs';
                        severity = 'high';
                    }
                    else if (path.includes('backup') || path.includes('.sql') || path.includes('dump')) {
                        fileType = 'backup';
                        severity = 'critical';
                    }
                    else if (path.includes('config') || path.includes('.env') || path.includes('settings')) {
                        fileType = 'config';
                        severity = 'critical';
                    }
                    result.exposedFiles.push({
                        path,
                        type: fileType,
                        accessible: true
                    });
                    result.findings.push({
                        type: 'file_exposure',
                        severity,
                        title: `Sensitive file exposed: ${path}`,
                        description: `File ${path} is publicly accessible and may contain sensitive information`,
                        cwe: 'CWE-200'
                    });
                }
                // Rate limiting
                await new Promise(resolve => setTimeout(resolve, 200));
            }
            catch (error) {
                // File not accessible or network error
            }
        }
        // Check for .git directory exposure
        try {
            const gitConfigResponse = await axios_1.default.get(`${baseUrl}/.git/config`, {
                timeout: 5000,
                validateStatus: () => true,
                headers: {
                    'User-Agent': config.userAgent
                }
            });
            if (gitConfigResponse.status === 200) {
                result.findings.push({
                    type: 'file_exposure',
                    severity: 'critical',
                    title: 'Git repository exposed',
                    description: 'The .git directory is publicly accessible, allowing complete source code download',
                    cwe: 'CWE-540'
                });
            }
        }
        catch (error) {
            // .git not accessible
        }
        // Check for directory listing
        if (config.intensity === 'active' || config.intensity === 'aggressive') {
            const dirsToCheck = ['/uploads/', '/files/', '/images/', '/assets/', '/backup/'];
            for (const dir of dirsToCheck) {
                try {
                    const response = await axios_1.default.get(`${baseUrl}${dir}`, {
                        timeout: 5000,
                        validateStatus: () => true,
                        headers: {
                            'User-Agent': config.userAgent
                        }
                    });
                    if (response.status === 200 && response.data.includes('Index of')) {
                        result.findings.push({
                            type: 'directory_listing',
                            severity: 'medium',
                            title: `Directory listing enabled: ${dir}`,
                            description: `Directory ${dir} has listing enabled, exposing file structure`,
                            cwe: 'CWE-548'
                        });
                    }
                    await new Promise(resolve => setTimeout(resolve, 200));
                }
                catch (error) {
                    // Directory not accessible
                }
            }
        }
    }
    catch (error) {
        console.error(`Info disclosure check error for ${url}:`, error);
    }
    return result;
}
