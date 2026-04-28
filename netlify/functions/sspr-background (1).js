/**
 * Smart Seller Protection Report™ — Netlify Background Function
 * File: netlify/functions/sspr-background.js
 *
 * Architecture:
 *  - Receives folder ID + metadata from browser
 *  - Downloads A2 (disclosure) or A3 (condition) PDFs via service account
 *  - Classifies files: READ (disclosure docs) vs INVENTORY (large reports)
 *  - Batches READ files in groups of 3 → Claude native PDF blocks
 *  - Extracts findings per group, synthesizes full SSPR report
 *  - Fires completed report to Pabbly webhook → Google Doc
 */

const https = require('https');

// ─── Config ───────────────────────────────────────────────────────────────────
const PER_FILE_CAP_KB   = 6144;   // 6MB per file hard cap
const GROUP_SIZE        = 3;      // files per Claude call

// ─── File classification ──────────────────────────────────────────────────────
// Disclosure mode — always READ these
const DISCLOSURE_READ_PATTERNS = [
  /\btds\b/i, /transfer.?disclos/i,
  /\bspq\b/i, /seller.?property.?quest/i,
  /\bavid\b/i, /visual.?inspect/i,
  /nhd.?signature/i, /nhd[-_]sig/i,
  /\bsbsa\b/i, /statewide.?buyer/i,
  /firpta/i, /earthquake/i, /\bwfda\b/i,
  /disclosure.?cover/i, /sacto.?disclos/i,
  /\blpd\b/i, /lead.?paint/i,
  /\bsbsa\b/i, /disclosures.?disclaimers/i,
];

// Always INVENTORY these (large files — confirm present, don't read)
const INVENTORY_PATTERNS = [
  /nhd.?full/i, /nhd.?report/i,
  /prelim/i, /preliminary.?title/i, /title.?report/i,
  /inspection.?report/i, /home.?inspect/i,
  /pest.?report/i, /termite.?report/i,
  /roof.?inspect/i, /sewer/i, /chimney/i,
];

const SMALL_FILE_THRESHOLD_KB = 500; // Unknown files under 500KB → READ

function classifyFile(filename, sizeKB) {
  for (const p of INVENTORY_PATTERNS) {
    if (p.test(filename)) return 'INVENTORY';
  }
  for (const p of DISCLOSURE_READ_PATTERNS) {
    if (p.test(filename)) return 'READ';
  }
  if (sizeKB < SMALL_FILE_THRESHOLD_KB) return 'READ';
  return 'READ'; // For SSPR, default to READ — these are all disclosure docs
}

// ─── Google Auth (Service Account JWT) ───────────────────────────────────────

function base64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getGoogleAccessToken() {
  const rawKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!rawKey) throw new Error('GOOGLE_SERVICE_ACCOUNT_KEY not set');
  let key;
  try { key = JSON.parse(rawKey); }
  catch (e) {
    try { key = JSON.parse(rawKey.trim().replace(/^"|"$/g, '')); }
    catch (e2) { throw new Error('Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY'); }
  }
  const privateKey = key.private_key.replace(/\\n/g, '\n');
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claim  = base64url(JSON.stringify({
    iss: key.client_email,
    scope: 'https://www.googleapis.com/auth/drive.readonly',
    aud: 'https://oauth2.googleapis.com/token',
    exp: now + 3600, iat: now
  }));
  const { createSign } = require('crypto');
  const sign = createSign('RSA-SHA256');
  sign.update(`${header}.${claim}`);
  const sig = sign.sign(privateKey, 'base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const jwt = `${header}.${claim}.${sig}`;

  return new Promise((resolve, reject) => {
    const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        const parsed = JSON.parse(data);
        if (parsed.access_token) resolve(parsed.access_token);
        else reject(new Error('Token error: ' + data));
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Drive helpers ────────────────────────────────────────────────────────────

function driveRequest(path, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com', path, method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { resolve({ error: 'JSON parse failed', raw: data.substring(0, 200) }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function listFolder(folderId, token) {
  const q      = encodeURIComponent(`'${folderId}' in parents and trashed = false`);
  const fields = encodeURIComponent('files(id,name,mimeType,size)');
  const result = await driveRequest(`/drive/v3/files?q=${q}&fields=${fields}&pageSize=100`, token);
  return result.files || [];
}

async function downloadBase64(fileId, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com',
      path: `/drive/v3/files/${fileId}?alt=media`,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('base64')));
    });
    req.on('error', reject);
    req.end();
  });
}

// ─── HTTP POST helper ─────────────────────────────────────────────────────────

function postJSON(urlString, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const url  = new URL(urlString);
    const req  = https.request({
      hostname: url.hostname, path: url.pathname + url.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Claude API call with native PDF document blocks ─────────────────────────

async function callClaude(files, promptText) {
  return new Promise((resolve, reject) => {
    const messageContent = [];

    // Attach each PDF as a native document block
    for (const f of files) {
      if (f.base64) {
        messageContent.push({
          type: 'document',
          source: { type: 'base64', media_type: 'application/pdf', data: f.base64 },
          title: f.filename
        });
      }
    }
    messageContent.push({ type: 'text', text: promptText });

    const requestBody = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      system: `You are a highly experienced California real estate advisor with 22 years as a listing agent and 18 years in construction. You read actual transaction documents and extract precise findings.

CRITICAL: Only report what you can directly read from the attached document content. Never fabricate, invent, or guess any information. If you cannot find something, say so explicitly.

NHD RULE: Only report hazard zones that are literally checked YES or marked applicable in the NHD. Do not assume or infer any hazard type not explicitly indicated.

AVID RULE: AVID-LA and AVID-BA are agent visual observations, NOT professional inspections. Use language like "agent noted" or "agent observed." Never classify an AVID item as High concern. AVID findings are observational only and may warrant professional follow-up.

Plain text output only. No markdown. No asterisks. No pound signs.`,
      messages: [{ role: 'user', content: messageContent }]
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'pdfs-2024-09-25'
      }
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (parsed.error) { resolve({ error: parsed.error.message, text: '' }); return; }
          const text = parsed.content?.filter(c => c.type === 'text').map(c => c.text).join('') || '';
          resolve({ text });
        } catch (e) { resolve({ error: e.message, text: '' }); }
      });
    });
    req.on('error', err => resolve({ error: err.message, text: '' }));
    req.write(requestBody);
    req.end();
  });
}

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const body = JSON.parse(event.body || '{}');
  const {
    folderId, folderName, reportMode,
    address, seller, agentName, agentDre,
    date, brokerageName, pabblyWebhook: pabblyKey
  } = body;

  // Resolve webhook URL from env vars — never trust browser payload for this
  const pabblyWebhook = pabblyKey === 'PABBLY_CONDITION'
    ? (process.env.PABBLY_CONDITION_WEBHOOK || process.env.PABBLY_DISCLOSURE_WEBHOOK)
    : process.env.PABBLY_DISCLOSURE_WEBHOOK;

  console.log(`[SSPR] Starting ${reportMode} report for: ${folderName}`);

  const subfolderName = reportMode === 'disclosure' ? 'A2' : 'A3';

  try {
    // ── Google Auth ───────────────────────────────────────────────────────────
    const token = await getGoogleAccessToken();
    console.log('[SSPR] Google auth OK');

    // ── Navigate to transaction folder → Active Transaction → A2 or A3 ───────
    const parentContents = await listFolder(folderId, token);
    const activeFolder = parentContents.find(f =>
      f.name.includes('Active Transaction') && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!activeFolder) {
      await postJSON(pabblyWebhook, { status: 'error', error: 'Active Transaction folder not found', address, seller, agentName });
      return { statusCode: 202 };
    }

    const activeContents = await listFolder(activeFolder.id, token);
    const subFolder = activeContents.find(f =>
      f.name.includes(subfolderName) && f.mimeType === 'application/vnd.google-apps.folder'
    );
    if (!subFolder) {
      await postJSON(pabblyWebhook, { status: 'error', error: `${subfolderName} subfolder not found`, address, seller, agentName });
      return { statusCode: 202 };
    }

    console.log(`[SSPR] Found subfolder: ${subFolder.name}`);

    // ── List all PDFs in subfolder ────────────────────────────────────────────
    const allItems = await listFolder(subFolder.id, token);
    const pdfFiles = allItems.filter(f =>
      (f.mimeType === 'application/pdf' || f.name.toLowerCase().endsWith('.pdf')) &&
      f.mimeType !== 'application/vnd.google-apps.folder'
    );

    if (!pdfFiles.length) {
      await postJSON(pabblyWebhook, { status: 'error', error: `No PDFs found in ${subFolder.name}`, address, seller, agentName });
      return { statusCode: 202 };
    }

    // ── Classify and download READ files ─────────────────────────────────────
    const readFiles = [];
    const inventoryFiles = [];

    for (const file of pdfFiles) {
      const sizeKB = parseInt(file.size || 0) / 1024;
      if (sizeKB === 0) { console.log(`[SSPR] Skipped 0KB: ${file.name}`); continue; }

      const classification = classifyFile(file.name, sizeKB);

      if (classification === 'INVENTORY' || sizeKB > PER_FILE_CAP_KB) {
        inventoryFiles.push({ filename: file.name, sizeKB: Math.round(sizeKB) });
        console.log(`[SSPR] INVENTORY: ${file.name} (${Math.round(sizeKB)}KB)`);
        continue;
      }

      try {
        const base64 = await downloadBase64(file.id, token);
        readFiles.push({ filename: file.name, sizeKB: Math.round(sizeKB), base64 });
        console.log(`[SSPR] Downloaded: ${file.name} (${Math.round(sizeKB)}KB)`);
      } catch (err) {
        inventoryFiles.push({ filename: file.name, sizeKB: Math.round(sizeKB), error: err.message });
        console.log(`[SSPR] Download failed: ${file.name} — ${err.message}`);
      }
    }

    console.log(`[SSPR] READ: ${readFiles.length} | INVENTORY: ${inventoryFiles.length}`);

    // ── Batch process READ files through Claude ───────────────────────────────
    const groups = [];
    for (let i = 0; i < readFiles.length; i += GROUP_SIZE) {
      groups.push(readFiles.slice(i, i + GROUP_SIZE));
    }

    const allFindings = [];
    const allFileNames = [...readFiles.map(f => f.filename), ...inventoryFiles.map(f => f.filename)];

    for (let g = 0; g < groups.length; g++) {
      const group = groups[g];
      const pauseMs = g === 0 ? 5000 : 45000; // Rate limit protection
      console.log(`[SSPR] Group ${g + 1}/${groups.length}: pausing ${pauseMs / 1000}s…`);
      await new Promise(r => setTimeout(r, pauseMs));

      const fileList = group.map(f => `• ${f.filename} (${f.sizeKB}KB)`).join('\n');
      const otherFiles = allFileNames.filter(n => !group.find(f => f.filename === n));
      const invList = inventoryFiles.map(f => `• ${f.filename}`).join('\n');

      const groupPrompt = `DOCUMENT GROUP ${g + 1} OF ${groups.length} — READ EVERY DOCUMENT ATTACHED

Files in this group (attached as PDFs above):
${fileList}

${inventoryFiles.length > 0 ? `Also present in the transaction folder but NOT attached in this group (too large to read — confirm by filename only):\n${invList}` : ''}
${otherFiles.length > 0 ? `\nOther files being processed in separate groups: ${otherFiles.join(', ')}` : ''}

Read every attached document completely. Extract all relevant findings including:
- Document type and execution status (signed/unsigned/initialed)
- Party names as they appear in the document
- Property address as it appears
- Key disclosures, conditions, hazard zones, known defects
- Any flags a buyer's agent would challenge
- Any vague, blank, or contradictory sections

For NHD documents: Only report hazard zones that are explicitly checked YES or marked applicable. Quote the exact checkbox language.
For AVID documents: Note all agent observations but label them as "agent observed" and note they are not professional inspection findings.

Be specific and thorough. Quote exact language where relevant. This will be used to build a complete seller advisory report.`;

      console.log(`[SSPR] Calling Claude for group ${g + 1}: ${group.map(f => f.filename).join(', ')}`);
      const result = await callClaude(group, groupPrompt);

      if (result.error) {
        console.error(`[SSPR] Group ${g + 1} error: ${result.error}`);
        allFindings.push(`[GROUP ${g + 1} ERROR: ${result.error}]`);
      } else {
        console.log(`[SSPR] Group ${g + 1} complete — ${result.text.length} chars`);
        allFindings.push(`=== GROUP ${g + 1} FINDINGS (${group.map(f => f.filename).join(', ')}) ===\n${result.text}`);
      }
    }

    // ── Synthesize final report ───────────────────────────────────────────────
    console.log('[SSPR] Synthesizing final report…');
    await new Promise(r => setTimeout(r, 5000));

    const reportType   = reportMode === 'disclosure' ? 'Listing Disclosure Review' : 'In-Contract Condition Analysis';
    const combinedFindings = allFindings.join('\n\n');

    const inventorySection = inventoryFiles.length > 0
      ? `\n\nFILES PRESENT BY FILENAME (too large to read — confirm by filename):\n${inventoryFiles.map(f => `• ${f.filename} (${f.sizeKB}KB)`).join('\n')}`
      : '';

    const synthesisPrompt = reportMode === 'disclosure'
      ? buildDisclosureSynthesisPrompt(address, seller, agentName, agentDre, date, brokerageName, combinedFindings, inventorySection, allFileNames)
      : buildConditionSynthesisPrompt(address, seller, agentName, agentDre, date, brokerageName, combinedFindings, inventorySection, allFileNames);

    const synthesis = await callClaude([], synthesisPrompt);

    const reportBody = synthesis.error
      ? `ERROR DURING SYNTHESIS: ${synthesis.error}\n\nRAW FINDINGS:\n${combinedFindings}`
      : synthesis.text;

    // ── Fire Pabbly ───────────────────────────────────────────────────────────
    const streetOnly = address.split(/,|\s+(?:Sacramento|Rocklin|Elk Grove|Folsom|Roseville|Citrus Heights|Rancho Cordova)/i)[0].trim();

    await postJSON(pabblyWebhook, {
      status:           'complete',
      report_mode:      reportMode,
      property_address: address,
      street_address:   streetOnly,
      seller_name:      seller,
      date,
      agent_name:       agentName,
      agent_dre:        agentDre,
      brokerage_name:   brokerageName,
      folder_id:        folderId,
      folder_name:      folderName,
      report_body:      reportBody,
      files_read:       readFiles.length,
      files_inventory:  inventoryFiles.length
    });

    console.log('[SSPR] Complete — Pabbly fired');
    return { statusCode: 202 };

  } catch (err) {
    console.error('[SSPR] Fatal error:', err.message);
    try {
      await postJSON(pabblyWebhook, {
        status: 'error', error: err.message,
        address, seller, agentName, date
      });
    } catch (e) {}
    return { statusCode: 202 };
  }
};

// ─── Synthesis prompts ────────────────────────────────────────────────────────

function buildDisclosureSynthesisPrompt(address, seller, agentName, agentDre, date, brokerage, findings, inventorySection, allFiles) {
  return `You are synthesizing a complete SMART SELLER PROTECTION REPORT™ from document findings extracted in the previous steps.

FINDINGS FROM ALL DOCUMENT GROUPS:
${findings}
${inventorySection}

ALL FILES IN THIS TRANSACTION:
${allFiles.map(f => `• ${f}`).join('\n')}

Using ONLY the findings above (do not invent anything), generate the complete report below. Every section must be based on actual findings from the documents. If a section has nothing to report, say "Nothing to report" — do not fabricate content.

SMART SELLER PROTECTION REPORT™
Listing Disclosure Review

Property Address: ${address}
Seller Name: ${seller}
Date: ${date}
Prepared By: ${agentName} | ${brokerage}
Agent License #: ${agentDre}

----------------------------------------

EXECUTIVE SUMMARY

[Based on actual findings: overview of disclosure package completeness, risk level, key concerns, listing readiness]

Disclosure Package Status: [Complete / Incomplete / Needs Attention]
Overall Risk Level: [Low / Moderate / Elevated]
Listing Readiness: [Ready / Needs Work / Address Before Listing]

----------------------------------------

DOCUMENTS REVIEWED

[List every document from the findings above with its type and execution status as found]

----------------------------------------

DISCLOSURE COMPLETENESS CHECK

TDS (Transfer Disclosure Statement): [status from actual findings]
SPQ (Seller Property Questionnaire): [status from actual findings]
NHD (Natural Hazard Disclosure): [status from actual findings]
AVID-LA (Agent Visual Inspection): [status from actual findings]
Preliminary Title Report: [status from actual findings]
FIRPTA Affidavit: [status from actual findings]
Other documents present: [from actual findings]
Missing recommended disclosures: [only items confirmed missing from actual findings]

----------------------------------------

RISK FLAGS — ITEMS A BUYER'S AGENT WILL CHALLENGE

[For each material risk from actual document findings — do not include AVID observations as High risk:]
[FLAG TITLE IN ALL CAPS]
Source: [exact filename from findings]
Risk Level: [Low / Moderate / High]
Category: [Legal / Physical / Environmental / Title / Disclosure Gap]

[Description from actual findings]

Seller Recommendation:
[Specific action]

----------------------------------------

TITLE & OWNERSHIP REVIEW

[From Preliminary Title Report findings if present. If not present: note it is missing and recommend obtaining before listing.]

----------------------------------------

NATURAL HAZARD EXPOSURE

[From NHD findings — only report hazard zones explicitly marked applicable in the document. If flooding is indicated, report flooding. If seismic is not indicated, do not mention seismic.]

----------------------------------------

MISSING OR VAGUE DISCLOSURES

[Items from actual findings that are blank, vague, or contradictory]

----------------------------------------

PRE-LISTING RECOMMENDATIONS

Priority 1 — Must Address Before Listing:
[From actual findings]

Priority 2 — Recommended:
[From actual findings]

Priority 3 — Optional:
[From actual findings]

----------------------------------------

AGENT NOTES FOR LISTING CONSULTATION

[Specific talking points based on actual findings. Pricing impact. Days on market considerations.]

----------------------------------------

OVERALL LISTING READINESS

Disclosure Package: [Complete / Needs Attention]
Physical Condition: [Good / Fair / Needs Work]
Title Status: [Clean / Issues to Resolve]
Listing Risk: [Low / Moderate / Elevated]

[3-4 sentence summary based on actual findings]

----------------------------------------

BROKERAGE INFORMATION

Brokerage: ${brokerage}
Broker License #: 02066500
Agent: ${agentName}
Agent License #: ${agentDre}

This report was prepared for seller advisory purposes only and does not constitute legal advice. Agent verification required before listing.`;
}

function buildConditionSynthesisPrompt(address, seller, agentName, agentDre, date, brokerage, findings, inventorySection, allFiles) {
  return `You are synthesizing a complete SMART SELLER PROTECTION REPORT™ — Condition Analysis from document findings extracted in the previous steps.

FINDINGS FROM ALL DOCUMENT GROUPS:
${findings}
${inventorySection}

ALL FILES IN THIS TRANSACTION:
${allFiles.map(f => `• ${f}`).join('\n')}

Using ONLY the findings above, generate the complete report below. Every section must be based on actual document findings.

SMART SELLER PROTECTION REPORT™
In-Contract Condition Analysis

Property Address: ${address}
Seller Name: ${seller}
Date: ${date}
Prepared By: ${agentName} | ${brokerage}
Agent License #: ${agentDre}

----------------------------------------

EXECUTIVE SUMMARY

[From actual findings: condition overview, RFR status, negotiation position]

Overall Condition: [Good / Fair / Needs Work]
RFR Risk Level: [Low / Moderate / High]
Negotiation Position: [Strong / Neutral / Challenging]

----------------------------------------

DOCUMENTS REVIEWED

[List every document from findings with type and date/inspector if found]

----------------------------------------

INSPECTION FINDINGS SUMMARY

STRUCTURAL & FOUNDATION
[From actual inspection report findings]

ROOF
[From actual findings]

ELECTRICAL
[From actual findings]

PLUMBING
[From actual findings]

HVAC
[From actual findings]

PEST & WOOD DESTROYING ORGANISMS
[Section I vs Section II from actual findings]

OTHER FINDINGS
[From actual findings]

----------------------------------------

RFR ANALYSIS — ITEM BY ITEM

[For each RFR item found in documents:]
[ITEM NAME IN ALL CAPS]
Buyer Requested: [exact text from RFR]
Classification: [Legitimate / Aggressive / Unreasonable]
Seller Recommendation: [Accept / Counter / Decline]
Rationale: [based on actual findings]

----------------------------------------

NEGOTIATION STRATEGY

Items to ACCEPT: [with rationale from findings]
Items to COUNTER: [with counter-position]
Items to DECLINE: [with rationale]

Overall Recommended Response: [Credit / Repairs / Combination / As-Is]
Suggested Credit Amount: [range only if applicable]

----------------------------------------

COE RISK ASSESSMENT

[From actual findings — items that could jeopardize closing]

----------------------------------------

AGENT NOTES FOR SELLER CONVERSATION

[From actual findings — how to present, where seller has leverage]

----------------------------------------

OVERALL POSITION

Inspection Results: [Better / As Expected / Worse than expected]
RFR Reasonableness: [Reasonable / Slightly aggressive / Very aggressive]
Recommended Action: [Accept as submitted / Counter / Decline and defend]

[3-4 sentence summary from actual findings]

----------------------------------------

BROKERAGE INFORMATION

Brokerage: ${brokerage}
Broker License #: 02066500
Agent: ${agentName}
Agent License #: ${agentDre}

This report was prepared for seller advisory purposes only and does not constitute legal advice. Agent verification required before COE.`;
}
