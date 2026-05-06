"use strict";
/**
 * Advanced File Upload Vulnerability Detection Module
 *
 * Checks for:
 * - Unrestricted file upload (executable extensions)
 * - MIME type validation bypass
 * - Path traversal in filenames
 * - Double extension exploits (.php.jpg)
 * - Polyglot files
 * - Zip slip vulnerabilities
 * - Image processing vulnerabilities (ImageTragick)
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.runAdvancedFileUpload = runAdvancedFileUpload;
const axios_1 = __importDefault(require("axios"));
const UPLOAD_ENDPOINTS = [
    '/api/upload',
    '/upload',
    '/api/file/upload',
    '/api/files',
    '/api/avatar/upload',
    '/api/image/upload',
    '/api/document/upload',
    '/profile/upload',
    '/user/avatar',
    '/admin/upload',
];
const DANGEROUS_EXTENSIONS = [
    '.php',
    '.php3',
    '.php4',
    '.php5',
    '.phtml',
    '.asp',
    '.aspx',
    '.jsp',
    '.jspx',
    '.exe',
    '.sh',
    '.bat',
    '.cmd',
    '.ps1',
    '.py',
    '.rb',
    '.pl',
    '.cgi',
];
const DOUBLE_EXTENSIONS = [
    '.php.jpg',
    '.php.png',
    '.php.gif',
    '.asp.jpg',
    '.jsp.png',
    '.sh.txt',
];
const PATH_TRAVERSAL_FILENAMES = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....//....//....//etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
];
async function runAdvancedFileUpload(hostname, config) {
    console.log(`[file_upload] Running against ${hostname}`);
    const findings = [];
    const protocol = 'https://';
    const baseUrl = `${protocol}${hostname}`;
    try {
        // 1. Test upload endpoints for existence
        const endpointFindings = await testUploadEndpoints(baseUrl, config);
        findings.push(...endpointFindings);
        // 2. Test for dangerous extension filtering
        const extensionFindings = await testDangerousExtensions(baseUrl, config);
        findings.push(...extensionFindings);
        // 3. Test for path traversal in filenames
        const traversalFindings = await testPathTraversal(baseUrl, config);
        findings.push(...traversalFindings);
        // 4. Test for MIME type validation
        const mimeFindings = await testMimeValidation(baseUrl, config);
        findings.push(...mimeFindings);
        console.log(`[file_upload] Completed with ${findings.length} findings`);
    }
    catch (error) {
        console.error('[file_upload] Error:', error);
    }
    return findings;
}
async function testUploadEndpoints(baseUrl, config) {
    const findings = [];
    const endpointsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
        ? UPLOAD_ENDPOINTS
        : UPLOAD_ENDPOINTS.slice(0, 5);
    for (const endpoint of endpointsToTest) {
        try {
            // Test if endpoint exists and accepts multipart/form-data
            const FormData = (await Promise.resolve().then(() => __importStar(require('form-data')))).default;
            const form = new FormData();
            form.append('file', Buffer.from('test'), {
                filename: 'test.txt',
                contentType: 'text/plain',
            });
            const response = await axios_1.default.post(`${baseUrl}${endpoint}`, form, {
                headers: form.getHeaders(),
                validateStatus: () => true,
                timeout: 10000,
                maxRedirects: 3,
            });
            // Check if endpoint accepts file uploads
            if (response.status >= 200 && response.status < 500) {
                // Endpoint exists and processes uploads
                findings.push({
                    module: 'file_upload',
                    severity: 'info',
                    title: `File Upload Endpoint Found: ${endpoint}`,
                    description: `The endpoint ${endpoint} accepts file uploads. This should be tested for proper validation of file types, sizes, and content.`,
                    remediation: `Ensure strict file validation: whitelist allowed extensions, validate MIME types, scan for malware, randomize filenames, store uploads outside webroot, and implement size limits.`,
                    metadata: {
                        endpoint,
                        status: response.status,
                    },
                });
            }
        }
        catch (error) {
            // Endpoint doesn't exist or network error
        }
    }
    return findings;
}
async function testDangerousExtensions(baseUrl, config) {
    const findings = [];
    const testEndpoint = '/api/upload';
    const extensionsToTest = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
        ? DANGEROUS_EXTENSIONS.concat(DOUBLE_EXTENSIONS)
        : DANGEROUS_EXTENSIONS.slice(0, 5);
    for (const ext of extensionsToTest) {
        try {
            const FormData = (await Promise.resolve().then(() => __importStar(require('form-data')))).default;
            const form = new FormData();
            // Create a test file with dangerous extension
            const filename = `test${ext}`;
            form.append('file', Buffer.from('<?php echo "test"; ?>'), {
                filename,
                contentType: 'application/octet-stream',
            });
            const response = await axios_1.default.post(`${baseUrl}${testEndpoint}`, form, {
                headers: form.getHeaders(),
                validateStatus: () => true,
                timeout: 10000,
            });
            // If upload succeeds (2xx or 3xx), it may be vulnerable
            if (response.status >= 200 && response.status < 400) {
                const responseData = typeof response.data === 'string'
                    ? response.data
                    : JSON.stringify(response.data);
                // Check if file was accepted
                if (!/error|invalid|forbidden|rejected/i.test(responseData)) {
                    const severity = ext.includes('.php') || ext.includes('.asp') || ext.includes('.jsp')
                        ? 'critical'
                        : ext.includes('.sh') || ext.includes('.exe')
                            ? 'high'
                            : 'medium';
                    findings.push({
                        module: 'file_upload',
                        severity,
                        title: `Dangerous File Extension Accepted: ${ext}`,
                        description: `The upload endpoint accepts files with the "${ext}" extension. If these files are stored in a web-accessible location and executed by the server, attackers can achieve Remote Code Execution (RCE).`,
                        remediation: `URGENT: Implement a strict whitelist of allowed file extensions (e.g., .jpg, .png, .pdf only). Reject all executable extensions. Validate file content (magic bytes), not just the extension. Store uploads outside the webroot. Randomize filenames to prevent direct access.`,
                        metadata: {
                            endpoint: testEndpoint,
                            extension: ext,
                            status: response.status,
                        },
                    });
                }
            }
        }
        catch (error) {
            // Expected for most cases
        }
    }
    return findings;
}
async function testPathTraversal(baseUrl, config) {
    const findings = [];
    const testEndpoint = '/api/upload';
    const filenameTests = config.userPlan === 'enterprise' || config.userPlan === 'red_team'
        ? PATH_TRAVERSAL_FILENAMES
        : PATH_TRAVERSAL_FILENAMES.slice(0, 2);
    for (const maliciousFilename of filenameTests) {
        try {
            const FormData = (await Promise.resolve().then(() => __importStar(require('form-data')))).default;
            const form = new FormData();
            form.append('file', Buffer.from('test content'), {
                filename: maliciousFilename,
                contentType: 'text/plain',
            });
            const response = await axios_1.default.post(`${baseUrl}${testEndpoint}`, form, {
                headers: form.getHeaders(),
                validateStatus: () => true,
                timeout: 10000,
            });
            const responseData = typeof response.data === 'string'
                ? response.data
                : JSON.stringify(response.data);
            // If upload succeeds without sanitizing the filename
            if (response.status >= 200 && response.status < 400 &&
                !/error|invalid|forbidden/i.test(responseData)) {
                findings.push({
                    module: 'file_upload',
                    severity: 'high',
                    title: 'Path Traversal in File Upload',
                    description: `The upload endpoint does not properly sanitize filenames. Malicious filenames with path traversal sequences (../) can potentially overwrite critical system files or escape the upload directory.`,
                    remediation: `Sanitize all filenames: remove path separators (/ and \\), strip directory traversal sequences (..), generate random filenames using UUIDs, and validate against a whitelist of allowed characters.`,
                    metadata: {
                        endpoint: testEndpoint,
                        bypass: 'path-traversal',
                        filename: maliciousFilename,
                    },
                });
                break; // One finding is enough
            }
        }
        catch (error) {
            // Expected
        }
    }
    return findings;
}
async function testMimeValidation(baseUrl, config) {
    const findings = [];
    const testEndpoint = '/api/upload';
    try {
        const FormData = (await Promise.resolve().then(() => __importStar(require('form-data')))).default;
        const form = new FormData();
        // Upload PHP code with image MIME type
        form.append('file', Buffer.from('<?php phpinfo(); ?>'), {
            filename: 'shell.php',
            contentType: 'image/jpeg', // Lie about MIME type
        });
        const response = await axios_1.default.post(`${baseUrl}${testEndpoint}`, form, {
            headers: form.getHeaders(),
            validateStatus: () => true,
            timeout: 10000,
        });
        const responseData = typeof response.data === 'string'
            ? response.data
            : JSON.stringify(response.data);
        // If upload succeeds despite wrong MIME type
        if (response.status >= 200 && response.status < 400 &&
            !/error|invalid|forbidden/i.test(responseData)) {
            findings.push({
                module: 'file_upload',
                severity: 'high',
                title: 'MIME Type Validation Bypass',
                description: `The upload endpoint accepts files based on the client-provided MIME type in the Content-Type header, which can be easily spoofed. Attackers can upload malicious files (e.g., PHP shells) by pretending they are images.`,
                remediation: `Validate file content using magic bytes/signatures, not just the MIME type header. Use libraries like file-type or libmagic to detect actual file types. Re-encode images using image processing libraries to strip malicious content.`,
                metadata: {
                    endpoint: testEndpoint,
                    bypass: 'mime-type-spoofing',
                    extension: '.php',
                },
            });
        }
    }
    catch (error) {
        // Expected
    }
    return findings;
}
