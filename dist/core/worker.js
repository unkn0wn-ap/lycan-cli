"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const supabase_js_1 = require("@supabase/supabase-js");
const os_1 = require("os");
const reconnaissance_advanced_1 = require("./modules/reconnaissance-advanced");
const http_headers_1 = require("./modules/http_headers");
const port_scan_advanced_1 = require("./modules/port_scan_advanced");
const sqli_advanced_1 = require("./modules/sqli_advanced");
const xss_advanced_1 = require("./modules/xss_advanced");
const csrf_advanced_1 = require("./modules/csrf_advanced");
const idor_advanced_1 = require("./modules/idor_advanced");
const ssrf_advanced_1 = require("./modules/ssrf_advanced");
const file_upload_advanced_1 = require("./modules/file_upload_advanced");
const xxe_advanced_1 = require("./modules/xxe_advanced");
const csp_advanced_1 = require("./modules/csp_advanced");
const tls_advanced_1 = require("./modules/tls_advanced");
const cookies_advanced_1 = require("./modules/cookies_advanced");
const api_security_1 = require("./modules/api_security");
const info_disclosure_1 = require("./modules/info_disclosure");
const scanner_config_1 = require("./config/scanner-config");
// ─── Configuration ───────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const POLL_INTERVAL_MS = 5000;
const MAX_ATTEMPTS = 3;
const WORKER_ID = `${(0, os_1.hostname)()}-${process.pid}`;
if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    console.error('[worker] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.');
    process.exit(1);
}
const supabase = (0, supabase_js_1.createClient)(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
    auth: { persistSession: false },
});
async function runModule(moduleId, hostname, config) {
    console.log(`  [${moduleId}] Running against ${hostname}`);
    switch (moduleId) {
        case 'reconnaissance': return (0, reconnaissance_advanced_1.runAdvancedReconnaissance)(hostname, config);
        case 'http_security': return (0, http_headers_1.runHttpHeaders)(hostname);
        case 'port_scan': return (0, port_scan_advanced_1.runAdvancedPortScan)(hostname, config);
        case 'sqli': return (0, sqli_advanced_1.runAdvancedSqli)(hostname, config);
        case 'xss': return (0, xss_advanced_1.runAdvancedXss)(hostname, config);
        case 'csrf': return (0, csrf_advanced_1.runAdvancedCsrf)(hostname, config);
        case 'idor': return (0, idor_advanced_1.runAdvancedIdor)(hostname, config);
        case 'ssrf': return (0, ssrf_advanced_1.runAdvancedSsrf)(hostname, config);
        case 'file_upload': return (0, file_upload_advanced_1.runAdvancedFileUpload)(hostname, config);
        case 'xxe': return (0, xxe_advanced_1.runAdvancedXxe)(hostname, config);
        case 'csp': return (0, csp_advanced_1.runAdvancedCsp)(hostname, config);
        case 'tls': return (0, tls_advanced_1.runAdvancedTls)(hostname, config);
        case 'cookies': return (0, cookies_advanced_1.runAdvancedCookies)(hostname, config);
        case 'api_security': return (0, api_security_1.runApiSecurity)(hostname, config);
        case 'info_disclosure': return (0, info_disclosure_1.runInfoDisclosure)(hostname, config);
        default:
            console.log(`  [${moduleId}] Unknown module — skipping.`);
            return [];
    }
}
// ─── Score calculation (0-100) ───────────────────────────────────────────────
// Uses a logarithmic penalty system to avoid score going to 0 too easily
// First finding of each severity has full impact, subsequent ones have diminishing returns
function calculateScore(findings) {
    // Group findings by severity
    const bySeverity = findings.reduce((acc, f) => {
        if (!acc[f.severity])
            acc[f.severity] = 0;
        acc[f.severity]++;
        return acc;
    }, {});
    // Base penalties (first finding of each type)
    const basePenalties = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
    // Calculate total deduction with logarithmic scaling
    let totalDeduction = 0;
    for (const [severity, count] of Object.entries(bySeverity)) {
        const basePenalty = basePenalties[severity] ?? 0;
        if (count === 0 || basePenalty === 0)
            continue;
        // First finding gets full penalty, subsequent ones scale logarithmically
        // Formula: basePenalty * (1 + log2(count) * 0.5)
        // Examples:
        //   1 finding: 1.0x penalty
        //   2 findings: 1.5x penalty
        //   4 findings: 2.0x penalty
        //   8 findings: 2.5x penalty
        //   16 findings: 3.0x penalty
        const scaledPenalty = basePenalty * (1 + Math.log2(count) * 0.5);
        totalDeduction += scaledPenalty;
    }
    // Cap deduction at 95 (minimum score of 5 if any findings exist)
    totalDeduction = Math.min(totalDeduction, 95);
    return Math.max(5, Math.round(100 - totalDeduction));
}
// ─── Main poll loop ──────────────────────────────────────────────────────────
async function claimJob() {
    // Atomic claim: only one worker gets each job
    const { data: jobs, error: pendingErr } = await supabase
        .from('scan_jobs')
        .select('*')
        .eq('status', 'pending')
        .or(`attempts.is.null,attempts.lt.${MAX_ATTEMPTS}`)
        .order('created_at', { ascending: true })
        .limit(1);
    if (pendingErr) {
        console.error('[worker] Error fetching pending jobs:', pendingErr);
        return null;
    }
    const job = jobs?.[0];
    if (!job)
        return null;
    const { data: claimed, error } = await supabase
        .from('scan_jobs')
        .update({
        status: 'processing',
        worker_id: WORKER_ID,
        claimed_at: new Date().toISOString(),
        attempts: (job.attempts ?? 0) + 1,
    })
        .eq('id', job.id)
        .eq('status', 'pending') // guard against race condition
        .select()
        .single();
    if (error || !claimed)
        return null;
    return claimed;
}
async function processJob(job) {
    console.log(`[worker] Processing job ${job.id} — scan ${job.scan_id}`);
    // Get domain hostname
    const { data: domain, error: domainError } = await supabase
        .from('domains')
        .select('hostname')
        .eq('id', job.domain_id)
        .single();
    if (!domain || domainError) {
        await failJob(job.id, 'Domain not found.');
        return;
    }
    // Get user plan
    const { data: profile } = await supabase
        .from('profiles')
        .select('plan')
        .eq('id', job.user_id)
        .single();
    const userPlan = profile?.plan || 'free';
    // Build scan configuration based on user plan
    const scanConfig = (0, scanner_config_1.buildScanConfig)(job.scan_id, domain.hostname, userPlan);
    console.log(`[worker] Plan: ${userPlan} | Intensity: ${scanConfig.intensity}`);
    // Mark scan as running
    await supabase
        .from('scans')
        .update({ status: 'running', started_at: new Date().toISOString() })
        .eq('id', job.scan_id);
    const allFindings = [];
    const modules = Array.isArray(job.modules) ? job.modules : [];
    for (const moduleId of modules) {
        try {
            const findings = await runModule(moduleId, domain.hostname, scanConfig);
            allFindings.push(...findings);
            // Write partial results in real-time (Supabase Realtime fires here)
            await supabase
                .from('scans')
                .update({
                results: {
                    modules_completed: modules.slice(0, modules.indexOf(moduleId) + 1),
                    findings: allFindings,
                },
            })
                .eq('id', job.scan_id);
        }
        catch (err) {
            console.error(`  [${moduleId}] Error:`, err);
        }
    }
    const score = calculateScore(allFindings);
    // Final update — mark completed
    const { error: scanUpdateError } = await supabase
        .from('scans')
        .update({
        status: 'completed',
        score,
        results: {
            modules_requested: modules,
            modules_completed: modules,
            findings: allFindings,
        },
        completed_at: new Date().toISOString(),
    })
        .eq('id', job.scan_id);
    if (scanUpdateError) {
        console.error(`[worker] CRITICAL: Failed to update scan ${job.scan_id} to completed:`, scanUpdateError);
    }
    else {
        console.log(`[worker] ✓ Scan ${job.scan_id} marked as completed with score ${score}/100`);
    }
    const { error: jobUpdateError } = await supabase
        .from('scan_jobs')
        .update({ status: 'completed', completed_at: new Date().toISOString() })
        .eq('id', job.id);
    if (jobUpdateError) {
        console.error(`[worker] CRITICAL: Failed to update job ${job.id} to completed:`, jobUpdateError);
    }
    console.log(`[worker] Job ${job.id} done. Score: ${score}/100, Findings: ${allFindings.length}`);
}
async function failJob(jobId, error) {
    await supabase
        .from('scan_jobs')
        .update({ status: 'failed', error, completed_at: new Date().toISOString() })
        .eq('id', jobId);
}
async function poll() {
    try {
        const job = await claimJob();
        if (job) {
            await processJob(job).catch(async (err) => {
                console.error('[worker] Unhandled error:', err);
                await failJob(job.id, String(err));
                await supabase
                    .from('scans')
                    .update({ status: 'failed', error_message: String(err) })
                    .eq('id', job.scan_id);
            });
        }
    }
    catch (err) {
        console.error('[worker] Poll error:', err);
    }
}
// ─── Entry point ─────────────────────────────────────────────────────────────
console.log(`[worker] Started. ID: ${WORKER_ID}`);
console.log(`[worker] Polling every ${POLL_INTERVAL_MS}ms...`);
setInterval(poll, POLL_INTERVAL_MS);
poll(); // immediate first poll
