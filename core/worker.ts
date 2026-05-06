import { createClient } from '@supabase/supabase-js';
import { hostname } from 'os';
import { runAdvancedReconnaissance } from './modules/reconnaissance-advanced';
import { runHttpHeaders } from './modules/http_headers';
import { runPortScan } from './modules/port_scan';
import { runAdvancedPortScan } from './modules/port_scan_advanced';
import { runSqli } from './modules/sqli';
import { runAdvancedSqli } from './modules/sqli_advanced';
import { runXss } from './modules/xss';
import { runAdvancedXss } from './modules/xss_advanced';
import { runAdvancedCsrf } from './modules/csrf_advanced';
import { runAdvancedIdor } from './modules/idor_advanced';
import { runAdvancedSsrf } from './modules/ssrf_advanced';
import { runAdvancedFileUpload } from './modules/file_upload_advanced';
import { runAdvancedXxe } from './modules/xxe_advanced';
import { runAdvancedCsp } from './modules/csp_advanced';
import { runAdvancedTls } from './modules/tls_advanced';
import { runAdvancedCookies } from './modules/cookies_advanced';
import { runApiSecurity } from './modules/api_security';
import { runInfoDisclosure } from './modules/info_disclosure';
import { buildScanConfig } from './config/scanner-config';

// ─── Configuration ───────────────────────────────────────────────────────────

const SUPABASE_URL = process.env.SUPABASE_URL!;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY!;
const POLL_INTERVAL_MS = 5000;
const MAX_ATTEMPTS = 3;
const WORKER_ID = `${hostname()}-${process.pid}`;

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('[worker] SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

// ─── Module dispatch ─────────────────────────────────────────────────────────

type ModuleId = 'reconnaissance' | 'http_security' | 'port_scan' | 'sqli' | 'xss' | 'csrf' | 'idor' | 'ssrf' | 'file_upload' | 'xxe' | 'csp' | 'tls' | 'cookies' | 'api_security' | 'info_disclosure';

interface Finding {
  module: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  remediation?: string;
  payload?: string;
  cwe?: string;
}

async function runModule(moduleId: ModuleId, hostname: string, config: any): Promise<Finding[]> {
  console.log(`  [${moduleId}] Running against ${hostname}`);
  switch (moduleId) {
    case 'reconnaissance': return runAdvancedReconnaissance(hostname, config);
    case 'http_security':  return runHttpHeaders(hostname);
    case 'port_scan':      return runAdvancedPortScan(hostname, config);
    case 'sqli':           return runAdvancedSqli(hostname, config);
    case 'xss':            return runAdvancedXss(hostname, config);
    case 'csrf':           return runAdvancedCsrf(hostname, config);
    case 'idor':           return runAdvancedIdor(hostname, config);
    case 'ssrf':           return runAdvancedSsrf(hostname, config);
    case 'file_upload':    return runAdvancedFileUpload(hostname, config);
    case 'xxe':            return runAdvancedXxe(hostname, config);
    case 'csp':            return runAdvancedCsp(hostname, config);
    case 'tls':            return runAdvancedTls(hostname, config);
    case 'cookies':        return runAdvancedCookies(hostname, config);
    case 'api_security':   return runApiSecurity(hostname, config);
    case 'info_disclosure': return runInfoDisclosure(hostname, config);
    default:
      console.log(`  [${moduleId}] Unknown module — skipping.`);
      return [];
  }
}

// ─── Score calculation (0-100) ───────────────────────────────────────────────
// Uses a logarithmic penalty system to avoid score going to 0 too easily
// First finding of each severity has full impact, subsequent ones have diminishing returns

function calculateScore(findings: Finding[]): number {
  // Group findings by severity
  const bySeverity = findings.reduce((acc, f) => {
    if (!acc[f.severity]) acc[f.severity] = 0;
    acc[f.severity]++;
    return acc;
  }, {} as Record<string, number>);

  // Base penalties (first finding of each type)
  const basePenalties = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
  
  // Calculate total deduction with logarithmic scaling
  let totalDeduction = 0;
  
  for (const [severity, count] of Object.entries(bySeverity)) {
    const basePenalty = basePenalties[severity as keyof typeof basePenalties] ?? 0;
    if (count === 0 || basePenalty === 0) continue;
    
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
  if (!job) return null;

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

  if (error || !claimed) return null;
  return claimed;
}

async function processJob(job: Record<string, unknown>) {
  console.log(`[worker] Processing job ${job.id} — scan ${job.scan_id}`);

  // Get domain hostname
  const { data: domain, error: domainError } = await supabase
    .from('domains')
    .select('hostname')
    .eq('id', job.domain_id as string)
    .single();

  if (!domain || domainError) {
    await failJob(job.id as string, 'Domain not found.');
    return;
  }

  // Get user plan
  const { data: profile } = await supabase
    .from('profiles')
    .select('plan')
    .eq('id', job.user_id as string)
    .single();

  const userPlan = (profile?.plan as 'free' | 'basic' | 'red_team' | 'enterprise') || 'free';

  // Build scan configuration based on user plan
  const scanConfig = buildScanConfig(
    job.scan_id as string,
    domain.hostname,
    userPlan
  );

  console.log(`[worker] Plan: ${userPlan} | Intensity: ${scanConfig.intensity}`);

  // Mark scan as running
  await supabase
    .from('scans')
    .update({ status: 'running', started_at: new Date().toISOString() })
    .eq('id', job.scan_id as string);

  const allFindings: Finding[] = [];
  const modules = Array.isArray(job.modules) ? (job.modules as ModuleId[]) : [];

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
        .eq('id', job.scan_id as string);
    } catch (err) {
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
    .eq('id', job.scan_id as string);

  if (scanUpdateError) {
    console.error(`[worker] CRITICAL: Failed to update scan ${job.scan_id} to completed:`, scanUpdateError);
  } else {
    console.log(`[worker] ✓ Scan ${job.scan_id} marked as completed with score ${score}/100`);
  }

  const { error: jobUpdateError } = await supabase
    .from('scan_jobs')
    .update({ status: 'completed', completed_at: new Date().toISOString() })
    .eq('id', job.id as string);

  if (jobUpdateError) {
    console.error(`[worker] CRITICAL: Failed to update job ${job.id} to completed:`, jobUpdateError);
  }

  console.log(`[worker] Job ${job.id} done. Score: ${score}/100, Findings: ${allFindings.length}`);
}

async function failJob(jobId: string, error: string) {
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
        await failJob(job.id as string, String(err));
        await supabase
          .from('scans')
          .update({ status: 'failed', error_message: String(err) })
          .eq('id', job.scan_id as string);
      });
    }
  } catch (err) {
    console.error('[worker] Poll error:', err);
  }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

console.log(`[worker] Started. ID: ${WORKER_ID}`);
console.log(`[worker] Polling every ${POLL_INTERVAL_MS}ms...`);

setInterval(poll, POLL_INTERVAL_MS);
poll(); // immediate first poll
