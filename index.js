import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

/**
 * =========================
 * ENV
 * =========================
 */
const {
  NODE_ENV = "development",
  BRAIN_SECRET,
  AIRTABLE_API_KEY,
  AIRTABLE_BASE_ID,
  AIRTABLE_TABLE_NAME = "Leads",
  AIRTABLE_TIMEOUT_MS = "12000",
} = process.env;

const AIRTABLE_TIMEOUT = Number(AIRTABLE_TIMEOUT_MS) || 12000;

function requireEnv(name) {
  if (!process.env[name]) throw new Error(`Missing env var: ${name}`);
}

/**
 * =========================
 * UTIL
 * =========================
 */
function nowIso() {
  return new Date().toISOString();
}

function traceId() {
  return crypto.randomUUID();
}

function toStr(v) {
  return (v ?? "").toString().trim();
}

function lower(v) {
  return toStr(v).toLowerCase();
}

function normalizePhone(phone) {
  const digits = toStr(phone).replace(/\D/g, "");
  if (!digits) return "";
  // Keep last 10 digits for US-style matching (prevents +1 vs no +1 mismatch)
  return digits.length > 10 ? digits.slice(-10) : digits;
}

function normalizeAddress(addr) {
  return lower(addr)
    .replace(/\s+/g, " ")
    .replace(/[.,#]/g, "")
    .trim();
}

function truthy(v) {
  const s = lower(v);
  return s === "true" || s === "yes" || s === "1" || s === "y" || s === "checked" || s === "on";
}

function escapeAirtableString(s) {
  return toStr(s).replace(/'/g, "\\'");
}

function abortableTimeout(ms) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), ms);
  return { ctrl, id };
}

/**
 * =========================
 * SECURITY
 * =========================
 * Make must send header:
 *   x-brain-secret: <BRAIN_SECRET>
 */
function requireSecret(req, res, next) {
  if (!BRAIN_SECRET) {
    // Fail closed in production
    if (NODE_ENV === "production") {
      return res.status(500).json({ ok: false, error: "Server misconfigured (missing BRAIN_SECRET)" });
    }
    return next();
  }

  const secret = req.headers["x-brain-secret"];
  if (!secret || secret !== BRAIN_SECRET) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

/**
 * =========================
 * SCORING (Marshall-style)
 * =========================
 * Inputs expected (from Tally/Make):
 * - Owns property?
 * - Avg monthly bill
 * - Roof age (years)
 * - Sun exposure
 * - HOA?
 * - Annual true-up cost / high true-up bills (yes/no or numeric)
 * - Property type
 * - What matters most
 * - Approach to home improvement
 *
 * Output:
 * - Score (0-100ish)
 * - Tier (single-select friendly)
 * - Lead temperature
 * - Reject reasons (if any)
 * - Score reasons (human-readable)
 */
function scoreLead(lead) {
  const reasons = [];
  const rejectReasons = [];

  const owns = lower(lead["Owns property?"] ?? lead.owns_property ?? lead.owns ?? lead.own);
  const isOwner = owns.includes("yes") || owns.includes("true") || owns === "1" || owns.includes("own");

  // Hard gate: must be owner (you said this is key)
  if (!isOwner) {
    rejectReasons.push("Not homeowner");
    return {
      score: 0,
      tier: "Disqualified",
      lead_temperature: "Cold",
      reject_reasons: rejectReasons,
      score_reasons: "Not homeowner",
      marshall_eligible: false
    };
  } else {
    reasons.push("Homeowner");
  }

  let score = 30; // owner base

  // Avg monthly bill
  const billRaw = toStr(lead["Avg monthly bill"] ?? lead.avg_monthly_bill ?? lead.bill);
  const billNum = Number(billRaw.replace(/[^0-9.]/g, ""));
  if (!Number.isNaN(billNum) && billNum > 0) {
    if (billNum >= 250) { score += 25; reasons.push("High bill"); }
    else if (billNum >= 150) { score += 15; reasons.push("Mid bill"); }
    else { score += 5; reasons.push("Low bill"); }
  } else {
    // If bill is a single select string like "$150-$250", match loosely
    const billTxt = lower(billRaw);
    if (billTxt.includes("250")) { score += 25; reasons.push("High bill"); }
    else if (billTxt.includes("150")) { score += 15; reasons.push("Mid bill"); }
    else if (billTxt) { score += 8; reasons.push("Bill provided"); }
    else { score += 0; reasons.push("Bill unknown"); }
  }

  // Roof age
  const roofAgeRaw = toStr(lead["Roof age (years)"] ?? lead.roof_age_years ?? lead.roof_age);
  const roofAgeNum = Number(roofAgeRaw.replace(/[^0-9.]/g, ""));
  if (!Number.isNaN(roofAgeNum) && roofAgeNum > 0) {
    if (roofAgeNum <= 10) { score += 20; reasons.push("Roof <= 10 years"); }
    else if (roofAgeNum <= 20) { score += 10; reasons.push("Roof 10–20 years"); }
    else { score += 0; reasons.push("Roof > 20 years"); }
  } else {
    const r = lower(roofAgeRaw);
    if (r.includes("under") || r.includes("<") || r.includes("10")) { score += 20; reasons.push("Roof likely good"); }
    else if (r.includes("20")) { score += 10; reasons.push("Roof maybe"); }
    else { score += 0; reasons.push("Roof unknown"); }
  }

  // Sun exposure
  const sun = lower(lead["Sun exposure"] ?? lead.sun_exposure ?? "");
  if (sun.includes("full") || sun.includes("great") || sun.includes("high")) {
    score += 15; reasons.push("Good sun exposure");
  } else if (sun.includes("partial") || sun.includes("medium")) {
    score += 8; reasons.push("Medium sun exposure");
  } else if (sun) {
    score += 2; reasons.push("Low/unknown sun exposure");
  }

  // HOA (not a hard reject, but friction)
  const hoa = lower(lead["HOA?"] ?? lead.hoa ?? "");
  if (hoa.includes("yes") || hoa.includes("true")) {
    score -= 5; reasons.push("HOA friction");
  } else if (hoa.includes("no") || hoa.includes("false")) {
    reasons.push("No HOA");
  }

  // True-up bills (optional positive indicator of value)
  const trueUpRaw = toStr(lead["Annual true-up cost"] ?? lead.true_up ?? lead.trueup ?? "");
  const trueUpTxt = lower(trueUpRaw);
  const trueUpNum = Number(trueUpRaw.replace(/[^0-9.]/g, ""));
  if (!Number.isNaN(trueUpNum) && trueUpNum >= 500) {
    score += 8; reasons.push("High true-up cost");
  } else if (trueUpTxt.includes("yes") || trueUpTxt.includes("true")) {
    score += 6; reasons.push("True-up indicated");
  }

  // Property type (single family tends to be easier)
  const ptype = lower(lead["Property type"] ?? lead.property_type ?? "");
  if (ptype.includes("single")) { score += 5; reasons.push("Single family"); }
  else if (ptype.includes("mobile") || ptype.includes("manufact")) { score -= 5; reasons.push("Mobile/manufactured complexity"); }
  else if (ptype) { reasons.push("Property type noted"); }

  // Clamp
  if (score < 0) score = 0;
  if (score > 100) score = 100;

  // Tiering
  let tier = "Warm – Review Later";
  let temp = "Warm";
  let eligible = false;

  if (score >= 70) { tier = "Qualified – Send to Marshall"; temp = "Hot"; eligible = true; }
  else if (score >= 40) { tier = "Warm – Review Later"; temp = "Warm"; }
  else { tier = "Educational Only"; temp = "Cold"; }

  return {
    score,
    tier,
    lead_temperature: temp,
    reject_reasons: rejectReasons,
    score_reasons: reasons.join(" | "),
    marshall_eligible: eligible
  };
}

/**
 * =========================
 * AIRTABLE (Upsert)
 * =========================
 * Dedupe priority:
 * 1) Phone
 * 2) Email
 * 3) Address + Zip
 */
function airtableHeaders() {
  return {
    Authorization: `Bearer ${AIRTABLE_API_KEY}`,
    "Content-Type": "application/json",
  };
}

function airtableUrl(path) {
  // Table name must be URL-encoded
  return `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(AIRTABLE_TABLE_NAME)}${path}`;
}

function buildDedupeFormula({ phone, email, address, zip }) {
  const parts = [];

  if (phone) parts.push(`{Phone}='${escapeAirtableString(phone)}'`);
  if (email) parts.push(`LOWER({Email})='${escapeAirtableString(lower(email))}'`);
  if (address && zip) {
    parts.push(
      `AND(LOWER({Address})='${escapeAirtableString(lower(address))}', {Zip}='${escapeAirtableString(toStr(zip))}')`
    );
  } else if (address) {
    parts.push(`LOWER({Address})='${escapeAirtableString(lower(address))}'`);
  }

  if (!parts.length) return "";
  return `OR(${parts.join(",")})`;
}

async function airtableRequest(method, url, body) {
  const { ctrl, id } = abortableTimeout(AIRTABLE_TIMEOUT);
  try {
    const resp = await fetch(url, {
      method,
      headers: airtableHeaders(),
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });

    const text = await resp.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }

    if (!resp.ok) {
      const msg = data?.error?.message || data?.message || text || `HTTP ${resp.status}`;
      throw new Error(`Airtable ${method} failed: ${resp.status} ${msg}`);
    }
    return data;
  } finally {
    clearTimeout(id);
  }
}

async function airtableFindExisting({ phone, email, address, zip }) {
  const formula = buildDedupeFormula({ phone, email, address, zip });
  if (!formula) return null;

  const params = new URLSearchParams();
  params.set("maxRecords", "1");
  params.set("filterByFormula", formula);

  const url = airtableUrl(`?${params.toString()}`);
  const data = await airtableRequest("GET", url);

  return data.records?.[0] || null;
}

async function airtableCreate(fields) {
  const url = airtableUrl("");
  return airtableRequest("POST", url, { fields });
}

async function airtableUpdate(recordId, fields) {
  const url = airtableUrl(`/${recordId}`);
  return airtableRequest("PATCH", url, { fields });
}

/**
 * =========================
 * FIELD MAPPING (Tally/Make -> Airtable Leads table)
 * =========================
 *
 * You said: "Tally answers are same single selects as airtable"
 * So we write them directly into your existing columns.
 */
function buildAirtableFieldsFromLead(lead, scored, consentFlags, meta) {
  // Consent flags
  const optInEmail = consentFlags.opt_in_email;
  const optInSms = consentFlags.opt_in_sms;
  const outreachAllowed = optInEmail || optInSms;

  // If no opt-in, we mark Do not contact TRUE (safe default)
  const doNotContact = !outreachAllowed;

  // Use Tally provided fields if present
  const name = toStr(lead.name ?? lead["Lead name"] ?? lead["What is your name"]);
  const email = toStr(lead.email ?? lead["Email"] ?? lead["What is your best email"]);
  const phoneRaw = toStr(lead.phone ?? lead["Phone"] ?? lead["What is your best phone number"]);
  const phone = normalizePhone(phoneRaw) ? phoneRaw : phoneRaw; // store original; dedupe uses normalized separately

  const address = toStr(lead.address ?? lead["Address"] ?? lead["What is your property address you’re asking in regards to?"]);
  const city = toStr(lead.city ?? lead["City"]);
  const state = toStr(lead.state ?? lead["State"]);
  const zip = toStr(lead.zip ?? lead["Zip"] ?? lead["Zip/postal code"] ?? lead["Zip/postal code "]);

  // Property details
  const propertyType = toStr(lead.property_type ?? lead["Property type"] ?? lead["What type of property is this?"]);
  const roofType = toStr(lead.roof_type ?? lead["Roof type"] ?? lead["What is your roof made of?"]);
  const roofAgeYears = toStr(lead.roof_age_years ?? lead["Roof age (years)"] ?? lead["How old is your roof?"]);
  const sunExposure = toStr(lead.sun_exposure ?? lead["Sun exposure"] ?? lead["How much sun does your roof get?"]);
  const hoa = toStr(lead.hoa ?? lead["HOA?"] ?? lead["Is your home part of an HOA?"]);
  const owns = toStr(lead.owns_property ?? lead["Owns property?"] ?? lead["Do you own this property?"]);

  // Bills
  const avgMonthlyBill = toStr(lead.avg_monthly_bill ?? lead["Avg monthly bill"] ?? lead["What’s your average monthly electricity bill?"]);
  const trueUp = toStr(lead.true_up ?? lead["Annual true-up cost"] ?? lead["Have you received high true-up bills? (End of year PG&E even with solar)"]);

  // Preferences
  const whatMattersMost = toStr(lead.what_matters_most ?? lead["What matters most"] ?? lead["What matters MOST to you in a solar investment?"]);
  const approach = toStr(lead.approach ?? lead["Approach to home improvement"] ?? lead["Your approach to major home improvements"]);

  // Make/Tally meta
  const leadSource = toStr(lead.lead_source ?? lead["Lead source"] ?? meta.source_name ?? "Tally");

  return {
    // Identity / address
    "Lead name": name,
    "Phone": phoneRaw,
    "Email": email,
    "Address": address,
    "City": city,
    "State": state,
    "Zip": zip,

    // Intake answers
    "Property type": propertyType,
    "Roof type": roofType,
    "Roof age (years)": roofAgeYears,
    "Sun exposure": sunExposure,
    "HOA?": hoa,
    "Owns property?": owns,
    "Avg monthly bill": avgMonthlyBill,
    "Annual true-up cost": trueUp,
    "What matters most": whatMattersMost,
    "Approach to home improvement": approach,

    // Scoring outputs
    "Score": scored.score,
    "Tier": scored.tier,
    "Lead temperature": scored.lead_temperature,
    "Score reasons": scored.score_reasons,
    "Reject reasons": (scored.reject_reasons || []).join(" | "),
    "AI tier": scored.tier,                 // keep same unless you want separate taxonomy
    "Needs scoring": false,

    // Outreach controls
    "Opt-in email?": optInEmail,
    "Opt-in SMS?": optInSms,
    "Outreach allowed": outreachAllowed,
    "Do not contact": doNotContact,

    // Ops meta
    "Lead source": leadSource,
    "Internal notes": `[trace:${meta.trace_id}] Scored at ${nowIso()}`
  };
}

/**
 * Extract consent from incoming payload.
 * We accept:
 * - boolean true/false
 * - "yes"/"no"
 * - "checked"/"on"
 */
function extractConsentFlags(lead) {
  const emailConsent =
    lead.opt_in_email ??
    lead["Opt-in email?"] ??
    lead["Email consent checkbox"] ??
    lead.email_consent;

  const smsConsent =
    lead.opt_in_sms ??
    lead["Opt-in SMS?"] ??
    lead["SMS consent checkbox"] ??
    lead.sms_consent;

  return {
    opt_in_email: truthy(emailConsent),
    opt_in_sms: truthy(smsConsent),
  };
}

async function upsertLeadToAirtable(lead, scored, meta) {
  requireEnv("AIRTABLE_API_KEY");
  requireEnv("AIRTABLE_BASE_ID");
  requireEnv("AIRTABLE_TABLE_NAME");

  // Dedupe keys
  const phoneNorm = normalizePhone(lead.phone ?? lead["Phone"] ?? lead["What is your best phone number"]);
  const email = toStr(lead.email ?? lead["Email"] ?? lead["What is your best email"]);
  const address = toStr(lead.address ?? lead["Address"] ?? lead["What is your property address you’re asking in regards to?"]);
  const zip = toStr(lead.zip ?? lead["Zip"] ?? lead["Zip/postal code"]);

  const consentFlags = extractConsentFlags(lead);
  const fields = buildAirtableFieldsFromLead(lead, scored, consentFlags, meta);

  // Find existing
  const existing = await airtableFindExisting({
    phone: phoneNorm ? phoneNorm : "",
    email,
    address,
    zip
  });

  if (existing?.id) {
    const updated = await airtableUpdate(existing.id, fields);
    return { action: "updated", record_id: updated.id };
  } else {
    const created = await airtableCreate(fields);
    return { action: "created", record_id: created.id };
  }
}

/**
 * =========================
 * ENDPOINTS
 * =========================
 */

// Health check
app.get("/", (req, res) => {
  res.json({ ok: true, service: "renew-power-brain", time: nowIso() });
});

// Score only (no Airtable write)
app.post("/score", requireSecret, (req, res) => {
  const t = traceId();
  const lead = req.body?.lead ?? req.body ?? {};
  const scored = scoreLead(lead);
  const consent = extractConsentFlags(lead);

  const routing = {
    route_to_marshall: scored.tier === "Qualified – Send to Marshall",
    allow_sms: Boolean(consent.opt_in_sms),
    allow_email: Boolean(consent.opt_in_email),
    outreach_allowed: Boolean(consent.opt_in_sms || consent.opt_in_email),
    do_not_contact: !(consent.opt_in_sms || consent.opt_in_email),
  };

  res.json({ ok: true, trace_id: t, scored, consent, routing });
});

// Score + Upsert to Airtable (this is what Make should call)
app.post("/ingest", requireSecret, async (req, res) => {
  const t = traceId();
  const lead = req.body?.lead ?? req.body ?? {};
  const meta = {
    trace_id: t,
    source_name: toStr(req.body?.meta?.source_name ?? "Make/Tally"),
    source_run_id: toStr(req.body?.meta?.source_run_id ?? "")
  };

  try {
    const scored = scoreLead(lead);
    const consent = extractConsentFlags(lead);

    const airtable = await upsertLeadToAirtable(lead, scored, meta);

    const routing = {
      route_to_marshall: scored.tier === "Qualified – Send to Marshall",
      allow_sms: Boolean(consent.opt_in_sms),
      allow_email: Boolean(consent.opt_in_email),
      outreach_allowed: Boolean(consent.opt_in_sms || consent.opt_in_email),
      do_not_contact: !(consent.opt_in_sms || consent.opt_in_email),
    };

    res.json({
      ok: true,
      trace_id: t,
      airtable,
      scored,
      consent,
      routing
    });
  } catch (err) {
    console.error(`[${t}] ingest error:`, err);
    res.status(500).json({
      ok: false,
      trace_id: t,
      error: "Ingest failed",
      detail: NODE_ENV === "production" ? undefined : String(err?.message || err)
    });
  }
});

/**
 * =========================
 * START
 * =========================
 */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Renew Power brain running on port ${port}`));
