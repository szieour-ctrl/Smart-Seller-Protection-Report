/**
 * Smart Seller Protection Report™ — Netlify Background Function
 * netlify/functions/sspr-background.js
 *
 * Finds client folder by lastName + "Listing 2026" in RE Transactions root
 * Downloads A2 (disclosure) or A3 (condition) PDFs via service account
 * Batches through Claude with native PDF blocks
 * Fires completed report to Pabbly → Google Doc + email
 */

const https = require('https');

const ROOT_FOLDER_ID  = '1iuTI1fKo4IZps9hzXLPFoI3TUT3NaCKI'; // RE Transactions 2026
const PER_FILE_CAP_KB = 6144;  // 6MB per file
const GROUP_SIZE      = 5;     // files per Claude call

// ── Google Service Account Auth ───────────────────────────────────────────────
function base64url(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function getGoogleAccessToken() {
  const rawKey = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (!rawKey) throw new Error('GOOGLE_SERVICE_ACCOUNT_KEY not set');
  console.log('[SSPR] Key length:', rawKey.length, '| starts:', rawKey.substring(0,15));
  let key;
  try {
    key = JSON.parse(rawKey);
    console.log('[SSPR] Key parsed OK, email:', key.client_email);
  } catch(e) {
    console.log('[SSPR] Parse attempt 1 failed:', e.message);
    try {
      const trimmed = rawKey.trim().replace(/^['"]|['"]$/g, '');
      key = JSON.parse(trimmed);
      console.log('[SSPR] Key parsed on attempt 2, email:', key.client_email);
    } catch(e2) {
      throw new Error('Key parse failed. Length=' + rawKey.length + ' Starts=' + rawKey.substring(0,40));
    }
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

// ── Drive helpers ─────────────────────────────────────────────────────────────
function driveGet(path, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'www.googleapis.com', path, method: 'GET',
      headers: { Authorization: `Bearer ${token}` }
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ error: 'parse fail', raw: data.substring(0, 200) }); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function searchFolder(parentId, nameContains, token) {
  const q = encodeURIComponent(
    `'${parentId}' in parents and name contains '${nameContains}' and mimeType='application/vnd.google-apps.folder' and trashed=false`
  );
  const result = await driveGet(`/drive/v3/files?q=${q}&fields=files(id,name)&pageSize=10`, token);
  return result.files || [];
}

async function listPdfs(folderId, token) {
  const q = encodeURIComponent(
    `'${folderId}' in parents and trashed=false and (mimeType='application/pdf' or name contains '.pdf')`
  );
  const result = await driveGet(
    `/drive/v3/files?q=${q}&fields=files(id,name,size,mimeType)&orderBy=name&pageSize=100`,
    token
  );
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

// ── HTTP POST helper ──────────────────────────────────────────────────────────
function postJSON(urlString, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const url  = new URL(urlString);
    const req  = https.request({
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
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

// ── Claude API — native PDF document blocks ───────────────────────────────────
async function callClaude(files, promptText) {
  return new Promise((resolve, reject) => {
    const content = [];
    for (const f of files) {
      if (f.base64) {
        content.push({
          type: 'document',
          source: { type: 'base64', media_type: 'application/pdf', data: f.base64 },
          title: f.filename
        });
      }
    }
    content.push({ type: 'text', text: promptText });

    const body = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      system: `You are a highly experienced California real estate advisor with 22 years as a listing agent and 18 years in construction. You read actual transaction documents and extract precise findings.

CRITICAL: Only report what you can directly read from the attached document content. Never fabricate or guess. If you cannot find something, say so explicitly.

NHD RULE: Only report hazard zones literally checked YES or marked applicable in the NHD document. Never assume any hazard type.

AVID RULE: AVID-LA and AVID-BA are agent visual observations, NOT professional inspections. Use language like "agent noted" or "agent observed." Never classify an AVID-only item as High concern.

Plain text only. No markdown. No asterisks. No pound signs.`,
      messages: [{ role: 'user', content }]
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'pdfs-2024-09-25',
        'Content-Length': Buffer.byteLength(body)
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
        } catch(e) { resolve({ error: e.message, text: '' }); }
      });
    });
    req.on('error', err => resolve({ error: err.message, text: '' }));
    req.write(body);
    req.end();
  });
}

// ── Build disclosure flags from property conditions ───────────────────────────
function buildConditionFlags(yearBuilt, hoa, pool, community55, wellSeptic) {
  const flags = [];
  const year = parseInt(yearBuilt);
  if (year && year < 1978) flags.push('LEAD BASED PAINT DISCLOSURE REQUIRED (pre-1978 construction)');
  if (year && year < 1994) flags.push('WATER HEATER BRACING DISCLOSURE — verify compliance (pre-1994)');
  if (hoa === 'yes') flags.push('HOA DOCUMENTS REQUIRED — CC&Rs, bylaws, budget, meeting minutes, pending assessments');
  if (pool === 'yes') flags.push('POOL/SPA SAFETY DISCLOSURE — drain cover compliance, fencing, permits');
  if (community55 === 'yes') flags.push('55+ COMMUNITY — age verification disclosures and HOA rules required');
  if (wellSeptic === 'yes') flags.push('WELL/SEPTIC — water quality test, septic inspection, permit verification required');
  return flags.length > 0 ? '\n\nPROPERTY CONDITION FLAGS — VERIFY THESE DISCLOSURES ARE PRESENT:\n' + flags.join('\n') : '';
}

// ── Main handler ──────────────────────────────────────────────────────────────
exports.handler = async (event) => {
  const body = JSON.parse(event.body || '{}');
  const {
    sellerLastName, address, yearBuilt,
    reportMode, agentName, agentDre, date, brokerageName,
    hoa, pool, community55, wellSeptic,
    reportEmail
  } = body;

  const pabblyWebhook = reportMode === 'condition'
    ? (process.env.PABBLY_CONDITION_WEBHOOK || process.env.PABBLY_DISCLOSURE_WEBHOOK)
    : process.env.PABBLY_DISCLOSURE_WEBHOOK;

  const subfolderTarget = reportMode === 'disclosure' ? 'A2' : 'A3';
  const conditionFlags  = buildConditionFlags(yearBuilt, hoa, pool, community55, wellSeptic);

  console.log(`[SSPR] Starting ${reportMode} report — Seller: ${sellerLastName} | ${address}`);

  try {
    // ── Google Auth ───────────────────────────────────────────────────────────
    const token = await getGoogleAccessToken();
    console.log('[SSPR] Google auth OK');

    // ── Find client folder by lastName + "Listing 2026" ──────────────────────
    console.log(`[SSPR] Searching for: ${sellerLastName} Listing`);
    const clientFolders = await searchFolder(ROOT_FOLDER_ID, sellerLastName, token);
    const clientFolder  = clientFolders.find(f =>
      f.name.toLowerCase().includes(sellerLastName.toLowerCase()) &&
      f.name.toLowerCase().includes('listing')
    );

    if (!clientFolder) {
      console.error(`[SSPR] Client folder not found for: ${sellerLastName}`);
      await postJSON(pabblyWebhook, {
        status: 'error',
        error:  `No folder found matching "${sellerLastName} - Listing 2026" in RE Transactions 2026.`,
        address, seller_name: sellerLastName, agent_name: agentName, date,
        report_email: reportEmail
      });
      return { statusCode: 202 };
    }
    console.log(`[SSPR] Found client folder: ${clientFolder.name}`);

    // ── Navigate to 3. Active Transaction ────────────────────────────────────
    const activeFolders = await searchFolder(clientFolder.id, 'Active Transaction', token);
    if (!activeFolders.length) {
      await postJSON(pabblyWebhook, {
        status: 'error', error: '"3. Active Transaction" folder not found.',
        address, seller_name: sellerLastName, agent_name: agentName, date,
        report_email: reportEmail
      });
      return { statusCode: 202 };
    }
    const activeFolder = activeFolders[0];
    console.log(`[SSPR] Found: ${activeFolder.name}`);

    // ── Navigate to A5 (Smart Seller Protection Report folder) ───────────────
    const a5Folders = await searchFolder(activeFolder.id, 'A5', token);
    const a5FolderId = a5Folders.length ? a5Folders[0].id : null;
    const a5FolderName = a5Folders.length ? a5Folders[0].name : null;
    console.log('[SSPR] A5 folder: ' + (a5FolderName || 'NOT FOUND') + ' | ID: ' + (a5FolderId || 'none'));

    // ── Navigate to A2 or A3 ─────────────────────────────────────────────────
    const subFolders = await searchFolder(activeFolder.id, subfolderTarget, token);
    if (!subFolders.length) {
      await postJSON(pabblyWebhook, {
        status: 'error', error: `"${subfolderTarget}" subfolder not found.`,
        address, seller_name: sellerLastName, agent_name: agentName, date,
        report_email: reportEmail
      });
      return { statusCode: 202 };
    }
    const subFolder = subFolders[0];
    console.log(`[SSPR] Found: ${subFolder.name}`);

    // ── List PDFs ─────────────────────────────────────────────────────────────
    const pdfFiles = await listPdfs(subFolder.id, token);
    if (!pdfFiles.length) {
      await postJSON(pabblyWebhook, {
        status: 'error', error: `No PDFs found in ${subFolder.name}.`,
        address, seller_name: sellerLastName, agent_name: agentName, date,
        report_email: reportEmail
      });
      return { statusCode: 202 };
    }
    console.log(`[SSPR] Found ${pdfFiles.length} PDFs`);

    // ── Download files under cap ──────────────────────────────────────────────
    const readFiles      = [];
    const inventoryFiles = [];

    for (const file of pdfFiles) {
      const sizeKB = Math.round(parseInt(file.size || 0) / 1024);
      if (sizeKB === 0) continue;

      if (sizeKB > PER_FILE_CAP_KB) {
        inventoryFiles.push({ filename: file.name, sizeKB });
        console.log(`[SSPR] Too large, inventory only: ${file.name} (${sizeKB}KB)`);
        continue;
      }
      try {
        const base64 = await downloadBase64(file.id, token);
        readFiles.push({ filename: file.name, sizeKB, base64 });
        console.log(`[SSPR] Downloaded: ${file.name} (${sizeKB}KB)`);
      } catch(err) {
        inventoryFiles.push({ filename: file.name, sizeKB, error: err.message });
      }
    }

    console.log(`[SSPR] READ: ${readFiles.length} | INVENTORY: ${inventoryFiles.length}`);

    // ── Batch through Claude ──────────────────────────────────────────────────
    const groups = [];
    for (let i = 0; i < readFiles.length; i += GROUP_SIZE) {
      groups.push(readFiles.slice(i, i + GROUP_SIZE));
    }

    const allFindings = [];
    const allFileNames = [
      ...readFiles.map(f => f.filename),
      ...inventoryFiles.map(f => f.filename)
    ];

    for (let g = 0; g < groups.length; g++) {
      const group = groups[g];
      await new Promise(r => setTimeout(r, g === 0 ? 2000 : 5000));
      console.log(`[SSPR] Calling Claude — group ${g + 1}/${groups.length}`);

      const invList  = inventoryFiles.map(f => `• ${f.filename} (${f.sizeKB}KB — too large, confirm by filename)`).join('\n');
      const otherNames = allFileNames.filter(n => !group.find(f => f.filename === n));

      const groupPrompt =
`DOCUMENT GROUP ${g + 1} OF ${groups.length} — READ EVERY ATTACHED PDF COMPLETELY

Files attached in this group:
${group.map(f => `• ${f.filename} (${f.sizeKB}KB)`).join('\n')}
${inventoryFiles.length ? `\nPresent by filename only (too large to attach):\n${invList}` : ''}
${otherNames.length ? `\nProcessed in other groups: ${otherNames.join(', ')}` : ''}
${conditionFlags}

Read every attached document completely — every page, every section, every checkbox.
Extract all relevant findings:
- Document type and full execution status (signed/unsigned/initialed by whom)
- Property address as it appears in the document
- Party names exactly as written
- All disclosures, known defects, conditions, hazard zones
- Any vague, blank, or contradictory sections
- Any flags a buyer's agent would challenge

NHD: Quote exact checkbox language — only report zones marked YES or applicable.
AVID: Label all findings as "agent observed" — these are not professional inspection findings.

Be specific and thorough. Quote exact document language where relevant.`;

      const result = await callClaude(group, groupPrompt);
      if (result.error) {
        console.error(`[SSPR] Group ${g + 1} error: ${result.error}`);
        allFindings.push(`[GROUP ${g + 1} ERROR: ${result.error}]`);
      } else {
        console.log(`[SSPR] Group ${g + 1} complete — ${result.text.length} chars`);
        allFindings.push(`=== GROUP ${g + 1} (${group.map(f => f.filename).join(', ')}) ===\n${result.text}`);
      }
    }

    // ── Synthesize final report ───────────────────────────────────────────────
    console.log('[SSPR] Synthesizing…');
    await new Promise(r => setTimeout(r, 2000));

    const invSection = inventoryFiles.length
      ? `\nFILES CONFIRMED PRESENT BY FILENAME (too large to read):\n${inventoryFiles.map(f => `• ${f.filename}`).join('\n')}`
      : '';

    const synthesisPrompt = reportMode === 'disclosure'
      ? buildDisclosurePrompt(address, sellerLastName, agentName, agentDre, date, brokerageName, allFindings.join('\n\n'), invSection, allFileNames, conditionFlags, yearBuilt, hoa, pool, community55, wellSeptic)
      : buildConditionPrompt(address, sellerLastName, agentName, agentDre, date, brokerageName, allFindings.join('\n\n'), invSection, allFileNames);

    const synthesis = await callClaude([], synthesisPrompt);
    const reportBody = synthesis.error
      ? `SYNTHESIS ERROR: ${synthesis.error}\n\nRAW FINDINGS:\n${allFindings.join('\n\n')}`
      : synthesis.text;

    // ── Fire Pabbly ───────────────────────────────────────────────────────────
    const streetOnly = address.split(/,|\s+(?:Sacramento|Rocklin|Elk Grove|Folsom|Roseville|Citrus Heights|Rancho Cordova)/i)[0].trim();

    await postJSON(pabblyWebhook, {
      status:           'complete',
      report_mode:      reportMode,
      property_address: address,
      street_address:   streetOnly,
      seller_name:      sellerLastName,
      date,
      agent_name:       agentName,
      agent_dre:        agentDre,
      brokerage_name:   brokerageName,
      folder_id:        clientFolder.id,
      folder_name:      clientFolder.name,
      a5_folder_id:     a5FolderId,
      report_body:      reportBody,
      report_email:     reportEmail,
      files_read:       readFiles.length,
      files_inventory:  inventoryFiles.length
    });

    console.log('[SSPR] Complete — Pabbly fired');
    return { statusCode: 202 };

  } catch(err) {
    console.error('[SSPR] Fatal:', err.message);
    try {
      await postJSON(pabblyWebhook, {
        status: 'error', error: err.message,
        address, seller_name: sellerLastName,
        agent_name: agentName, date, report_email: reportEmail
      });
    } catch(e) {}
    return { statusCode: 202 };
  }
};

// ── Synthesis prompts ─────────────────────────────────────────────────────────

function buildDisclosurePrompt(address, seller, agentName, agentDre, date, brokerage, findings, invSection, allFiles, conditionFlags, yearBuilt, hoa, pool, community55, wellSeptic) {
  const year = parseInt(yearBuilt);
  const lbpRequired = year && year < 1978;
  return `Synthesize a complete SMART SELLER PROTECTION REPORT™ using ONLY the findings below. Never invent content.

FINDINGS FROM ALL DOCUMENT GROUPS:
${findings}
${invSection}

ALL FILES IN THIS TRANSACTION:
${allFiles.map(f => `• ${f}`).join('\n')}

PROPERTY CONDITIONS ENTERED BY AGENT:
Year Built: ${yearBuilt || 'Not provided'}
HOA Present: ${hoa}
Pool/Spa: ${pool}
55+ Community: ${community55}
Well/Septic: ${wellSeptic}
${conditionFlags}

SMART SELLER PROTECTION REPORT™
Listing Disclosure Review

Property Address: ${address}
Seller Name: ${seller}
Date: ${date}
Prepared By: ${agentName} | ${brokerage}
Agent License #: ${agentDre}

----------------------------------------

EXECUTIVE SUMMARY

[Based on actual findings — overview of disclosure package completeness, risk level, key concerns, listing readiness]

Disclosure Package Status: [Complete / Incomplete / Needs Attention]
Overall Risk Level: [Low / Moderate / Elevated]
Listing Readiness: [Ready / Needs Work / Address Before Listing]

----------------------------------------

DOCUMENTS REVIEWED

[List every document with type and execution status as found in the actual documents]

----------------------------------------

DISCLOSURE COMPLETENESS CHECK

TDS (Transfer Disclosure Statement): [status from findings]
SPQ (Seller Property Questionnaire): [status from findings]
NHD (Natural Hazard Disclosure): [status from findings]
AVID-LA (Agent Visual Inspection): [status from findings]
Preliminary Title Report: [status from findings]
FIRPTA Affidavit: [status from findings]
${lbpRequired ? 'Lead Based Paint Disclosure (REQUIRED — pre-1978): [status from findings]' : ''}
${hoa === 'yes' ? 'HOA Documents (REQUIRED): [status from findings]' : ''}
${pool === 'yes' ? 'Pool/Spa Disclosure (REQUIRED): [status from findings]' : ''}
${community55 === 'yes' ? '55+ Community Disclosures (REQUIRED): [status from findings]' : ''}
${wellSeptic === 'yes' ? 'Well/Septic Disclosure (REQUIRED): [status from findings]' : ''}
Other documents present: [from findings]
Missing recommended disclosures: [only items confirmed missing]

----------------------------------------

RISK FLAGS — ITEMS A BUYER'S AGENT WILL CHALLENGE

[For each material risk from actual findings. AVID items max Moderate risk:]
[FLAG TITLE IN ALL CAPS]
Source: [exact filename]
Risk Level: [Low / Moderate / High]
Category: [Legal / Physical / Environmental / Title / Disclosure Gap]

[Description from actual document findings]

Seller Recommendation:
[Specific action]

----------------------------------------

TITLE & OWNERSHIP REVIEW

[From Preliminary Title Report findings if present. If missing, note it and recommend obtaining before listing.]

----------------------------------------

NATURAL HAZARD EXPOSURE

[From NHD findings only — report ONLY hazard zones explicitly marked applicable. Do not mention zones marked not applicable.]

----------------------------------------

MISSING OR VAGUE DISCLOSURES

[Items from actual findings that are blank, vague, or contradictory. Missing permits.]

----------------------------------------

PRE-LISTING RECOMMENDATIONS

Priority 1 — Must Address Before Listing:
[From actual findings plus any required disclosures for property conditions]

Priority 2 — Recommended:
[From actual findings]

Priority 3 — Optional:
[From actual findings]

----------------------------------------

AGENT NOTES FOR LISTING CONSULTATION

[Specific talking points from actual findings. Pricing impact. Days on market considerations.]

----------------------------------------

OVERALL LISTING READINESS

Disclosure Package: [Complete / Needs Attention]
Physical Condition: [Good / Fair / Needs Work]
Title Status: [Clean / Issues to Resolve]
Listing Risk: [Low / Moderate / Elevated]

[3-4 sentence summary from actual findings]

----------------------------------------

BROKERAGE INFORMATION

Brokerage: ${brokerage}
Broker License #: 02066500
Agent: ${agentName}
Agent License #: ${agentDre}

This report was prepared for seller advisory purposes only and does not constitute legal advice. Agent verification required before listing.`;
}

function buildConditionPrompt(address, seller, agentName, agentDre, date, brokerage, findings, invSection, allFiles) {
  return `Synthesize a complete SMART SELLER PROTECTION REPORT™ — Condition Analysis using ONLY the findings below. Never invent content.

FINDINGS FROM ALL DOCUMENT GROUPS:
${findings}
${invSection}

ALL FILES IN THIS TRANSACTION:
${allFiles.map(f => `• ${f}`).join('\n')}

SMART SELLER PROTECTION REPORT™
In-Contract Condition Analysis

Property Address: ${address}
Seller Name: ${seller}
Date: ${date}
Prepared By: ${agentName} | ${brokerage}
Agent License #: ${agentDre}

----------------------------------------

EXECUTIVE SUMMARY

[From actual findings — condition overview, RFR status, negotiation position]

Overall Condition: [Good / Fair / Needs Work]
RFR Risk Level: [Low / Moderate / High]
Negotiation Position: [Strong / Neutral / Challenging]

----------------------------------------

DOCUMENTS REVIEWED

[List every document with type and inspector/date from findings]

----------------------------------------

INSPECTION FINDINGS SUMMARY

STRUCTURAL & FOUNDATION
[From actual inspection findings]

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

[For each RFR item from actual documents:]
[ITEM NAME IN ALL CAPS]
Buyer Requested: [exact text from RFR]
Classification: [Legitimate / Aggressive / Unreasonable]
Seller Recommendation: [Accept / Counter / Decline]
Rationale: [based on actual findings]

----------------------------------------

NEGOTIATION STRATEGY

Items to ACCEPT: [with rationale]
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
