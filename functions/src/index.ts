import { setGlobalOptions } from "firebase-functions/v2";
import { onRequest } from "firebase-functions/v2/https";
import * as admin from "firebase-admin";
import type { Request, Response } from "express";

admin.initializeApp();
setGlobalOptions({ region: "us-central1", maxInstances: 10 });

const SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"; //Google safe browsing REST api
const SHORTENER_HOSTS = new Set([ 
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "cutt.ly",
  "rebrand.ly",
]);//a few of the shorend URLs to be SUS, need to add more. 
const SUSPICIOUS_ATTACHMENT_RE = /\.(?:exe|scr|js|jar|iso|img|zip|rar)\b/i; //regexs that flags the .exe or what not
const URGENCY_RE= /\b(urgent|immediately|action required|verify your account|your account will|suspend(?:ed)?|payment required)\b/i; //checks for these types of imedite words
const CREDENTIAL_RE= /\b(login|sign in|enter your password|reset your password|confirm your identity|update billing)\b/i;
const RAW_IP_HOST_RE= /^\d{1,3}(?:\.\d{1,3}){3}$/;
const LOOKALIKE_BASE_DOMAINS = [
  "google.com",
  "gmail.com",
  "microsoft.com",
  "outlook.com",
  "office.com",
  "apple.com",
  "icloud.com",
  "paypal.com",
  "bankofamerica.com",
  "wellsfargo.com",
  "chase.com",
  "amazon.com",
];
const LOOKALIKE_THRESHOLD = 2; //this is the  limit to allow before scoreing it negativly
const SCORING = Object.freeze({
  safeBrowsing: { base: 60, perHit: 10, max: 80, why: "Block-list hit is strongest indicator" }, //block list from the api
  idn: { perHost: 12, max: 24, why: "IDN can mask lookalikes; capped to avoid over-weighting" }, //lookalike
  shortener: { perHost: 10, max: 20, why: "Shorteners obscure destination" }, 
  rawIp: { perHost: 15, max: 30, why: "Raw IP hosts often used in kits" },
  insecure: { perUrl: 5, max: 15, why: "HTTP links only mildly suspicious" },
  mismatch: { points: 15, why: "Display text ≠ href is a classic phish tell" },
  lookalike: { perHost: 15, max: 30, why: "Edit distance on registrable domain" },
  content: { urgency: 10, creds: 15, max: 25, why: "Language indicators" },
  header: { attRef: 25, replyMismatch: 20, max: 45, why: "Header-level signals" },
  verdicts: { potential: 25, high: 50, known: 75 },
} as const);

type AnalyzerVerdict = "Likely Safe" | "Potentially Phishing" | "High Risk" | "Known Dangerous";

interface AnalyzerInput { //describes the shape of the data going into/out of analyzeEmailLogic
  subject?: string;
  headers?: string;
  body: string;
  links?: string[];
}

interface AnalyzerResult { //^
  score: number;
  verdict: AnalyzerVerdict;
  findings: string[];
}

async function lookupSafeBrowsing(urls: string[]): Promise<Set<string>> { //packages URLs and POSTs them to the Safe Browsing API using my secret key
  const apiKey = process.env.SAFE_BROWSING_API_KEY;
  if (!apiKey || urls.length === 0) return new Set();
  const payload = {
    client: { clientId: "phishhawk", clientVersion: "1.0.0" }, //returns this json
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: urls.map((url) => ({ url })),
    },
  };

  try {
    const response = await fetch(`${SAFE_BROWSING_ENDPOINT}?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      console.error("Safe Browsing request failed", response.status, response.statusText);
      return new Set();
    }

    const data = (await response.json()) as { matches?: Array<{ threat?: { url?: string } }> };
    const matches = new Set<string>();
    for (const match of data.matches ?? []) {
      const url = match?.threat?.url;
      if (url) matches.add(url);
    }
    return matches;
  } catch (err) {
    console.error("Safe Browsing lookup error", err);
    return new Set();
  }
}

function extractUrls(text: string): string[] { //Scans any text given to it
  if (!text) return [];
  const urls = new Set<string>();
  // URL detection is intentionally broad. i post-validate with URL().
  const urlRegex = /((https?:\/\/)?[a-z0-9\-.]+\.[a-z]{2,}(?:[:0-9]*)?(?:\/[^\s<>"']*)?)/gi;
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(text)) !== null) {
    let url = match[1];
    if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
    try {
      urls.add(new URL(url).toString());
    } catch {
      // ignore invalid urls (URL constructor throws)
    }
  }
  return Array.from(urls);
}

function hostOf(url: string): string {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return "";
  }
}

function hasPunycodeOrUnicode(host: string): boolean { //punycode checker, looks to see if diffrent/non normal characters are used
  if (!host) return false;
  if (host.includes("xn--")) return true;
  return /[\u0080-\uFFFF]/.test(host);
}

function isShortenerHost(host: string): boolean { //checks if the host is in SHORTENER_HOST
  if (!host) return false;
  return SHORTENER_HOSTS.has(host);
}

function isRawIpHost(host: string): boolean { //Checks to see literal Ipv4
  if (!host) return false;
  if (!RAW_IP_HOST_RE.test(host)) return false;
  return host.split(".").every((segment) => {
    const value = Number(segment);
    return value >= 0 && value <= 255;
  });
}

function findDisplayHrefMismatches(text: string): Array<{ display: string; href: string }> { // collects mismatches to flag EX: “text says paypal.com but link goes elsewhere.”
  const findings: Array<{ display: string; href: string }> = [];
  if (!text) return findings;

  const markdown = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/gi;
  let match: RegExpExecArray | null;
  while ((match = markdown.exec(text)) !== null) {
    const display = match[1];
    const href = match[2];
    const displayHost = extractHostCandidate(display);
    const hrefHost = hostOf(href);
    if (displayHost && hrefHost && displayHost !== hrefHost) {
      findings.push({ display: displayHost, href });
    }
  }

  const anchor = /<a[^>]*href="(https?:\/\/[^"]+)"[^>]*>(.*?)<\/a>/gi; // href host
  while ((match = anchor.exec(text)) !== null) {
    const href = match[1];
    const displayText = match[2].replace(/<[^>]+>/g, "");
    const displayHost = extractHostCandidate(displayText);
    const hrefHost = hostOf(href);
    if (displayHost && hrefHost && displayHost !== hrefHost) {
      findings.push({ display: displayHost, href });
    }
  }

  return findings;
}

function extractHostCandidate(text: string): string { //gets domain strings from text
  if (!text) return "";
  const explicit = text.match(/https?:\/\/([^/\s]+)/i);
  if (explicit?.[1]) return explicit[1].toLowerCase(); 
  const bare = text.match(/([a-z0-9\-.]+\.[a-z]{2,})/i); //regex hunts for any alphanumeric string with dots that ends in a TLD EX“visit security-example.co” the .co gets cought
  return bare?.[1] ? bare[1].toLowerCase() : "";
}

function parseHeaderDomain(headersText: string | undefined, headerName: string): string { //reads headers From or Reply-to
  if (!headersText) return "";
  // Header parsing is shallow; folded or encoded fields may slip through.
  // If we ingest raw RFC822 later, swap this for a proper MIME parser.
  const re = new RegExp(`^${headerName}:\\s*(.*)$`, "im");
  const match = re.exec(headersText);
  if (!match) return "";
  const value = match[1];
  const emailMatch = value.match(/<\s*([^>]+)\s*>/) || value.match(/([a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,})/i); // This chains two regex searches so whichever pattern hits first wins.
  if (!emailMatch) return "";
  const email = emailMatch[1] || "";
  if (!email) return "";
  return email.split("@")[1]?.toLowerCase() ?? "";
}

function extractDomainMentions(text: string): string[] { //scans prose for any word that looks like corp.example.com
  if (!text) return [];
  const domains = new Set<string>();
  const mentionRegex = /\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)\b/gi; //regex = start at a word boundary, grab a label that starts and ends with alphanumerics, allow dashes inside, then require at least one dot+label pair after it.
  let match: RegExpExecArray | null;
  while ((match = mentionRegex.exec(text)) !== null) {
    const domain = match[1].toLowerCase();
    if (domain && !domain.includes("..")) domains.add(domain);
  }
  return Array.from(domains);
}

function registrableDomain(host: string): string { //collapses a host EX: mail.secure.paypal.com -> paypal.com
  if (!host) return "";
  const labels = host.split(".").filter(Boolean); //splits on dots and removes empty strings 
  if (labels.length <= 2) return host;
  return labels.slice(-2).join(".");
}

/**
 * Levenshtein distance (O(|a|·|b|)) to spot near matches.
 * Mostly for spoofed domains; consider homoglyphs later.
 */
function levenshtein(a: string, b: string): number { //got this mostly online, but it measures edit distance between two strings
  if (a === b) return 0;
  if (!a) return b.length;
  if (!b) return a.length;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  const curr = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) curr[j] = prev[j - 1];
      else curr[j] = Math.min(prev[j - 1], prev[j], curr[j - 1]) + 1; //encodes the insert/delete/replace cost transition in the DP table;
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
  }
  return prev[b.length];
}

function detectLookalikeDomain(host: string): string | null { //compares a host against each known good brand
  if (!host) return null;
  const baseHost = registrableDomain(host);
  for (const legit of LOOKALIKE_BASE_DOMAINS) {
    if (baseHost === legit) continue;
    const distance = levenshtein(baseHost, legit); //domains go through the DP scorer and flags the legitimate brand
    if (distance > 0 && distance <= LOOKALIKE_THRESHOLD) {
      return legit;
    }
  }
  return null;
}

function verdictFor(score: number): AnalyzerVerdict { //takes the 0-100 and creates a verdict. 
  const { potential, high, known } = SCORING.verdicts;
  if (score >= known) return "Known Dangerous";
  if (score >= high) return "High Risk";
  if (score >= potential) return "Potentially Phishing";
  return "Likely Safe";
}

async function analyzeEmailLogic(input: AnalyzerInput): Promise<AnalyzerResult> {
  const body = input.body || "";
  const headers = input.headers || "";
  const findings: string[] = [];
  const providedLinks = Array.isArray(input.links) ? input.links : [];
  const urls = Array.from(new Set([...extractUrls(body), ...providedLinks]));
  const punyHosts = new Set<string>();
  const shortenerHosts = new Set<string>();
  const rawIpHosts = new Set<string>();
  const insecureLinks = new Set<string>();
  const lookalikeHosts = new Map<string, string>();

  for (const url of urls) { //URL classification, runs through each helper function any matches go to the sets
    const host = hostOf(url);
    if (!host) continue;
    if (hasPunycodeOrUnicode(host)) punyHosts.add(host);
    if (isShortenerHost(host)) shortenerHosts.add(host);
    if (isRawIpHost(host)) rawIpHosts.add(host);
    if (url.startsWith("http://")) insecureLinks.add(url);
    const spoofTarget = detectLookalikeDomain(host);
    if (spoofTarget) lookalikeHosts.set(host, spoofTarget);
  }

  const mentionLookalikes: string[] = [];
  const domainMentions = extractDomainMentions(body); //finds each mention
  for (const mention of domainMentions) {
    if (urls.some((url) => hostOf(url) === mention)) continue;
    const spoofTarget = detectLookalikeDomain(mention); // tries detectLookalikeDomain to see if the host is a near miss of a known brand or storing spoof 
    if (spoofTarget) mentionLookalikes.push(`${mention}≈${spoofTarget}`);
  }

  const mismatchExamples = findDisplayHrefMismatches(body);//scans html/markdown for were link text claims one host but the href points elsewhere
  const safeBrowsingHits = await lookupSafeBrowsing(urls); //calls Google’s Safe Browsing API.  If any URLs come back flagged itll assigs Safe Browsing points using the SCORING.safeBrowsing caps
  const safeBrowsingPoints = safeBrowsingHits.size
    ? Math.min(
      SCORING.safeBrowsing.base +
        (safeBrowsingHits.size - 1) * SCORING.safeBrowsing.perHit,
      SCORING.safeBrowsing.max,
    )
    : 0;
  if (safeBrowsingPoints > 0) { //If any exist it adds the configured mismatch 
    findings.push(`Safe Browsing flagged ${safeBrowsingHits.size} link(s)`);
  }

  const idnPoints = Math.min(
    punyHosts.size * SCORING.idn.perHost,
    SCORING.idn.max,
  );
  if (idnPoints > 0) {
    findings.push(`IDN/Punycode hosts detected: ${Array.from(punyHosts).slice(0, 3).join(", ")}`);
  }

  const shortenerPoints = Math.min(
    shortenerHosts.size * SCORING.shortener.perHost,
    SCORING.shortener.max,
  );
  if (shortenerPoints > 0) {
    findings.push(`URL shorteners detected: ${Array.from(shortenerHosts).join(", ")}`);
  }

  const rawIpPoints = Math.min(
    rawIpHosts.size * SCORING.rawIp.perHost,
    SCORING.rawIp.max,
  );
  if (rawIpPoints > 0) {
    findings.push(`Raw IP hosts detected: ${Array.from(rawIpHosts).join(", ")}`);
  }

  const insecurePoints = Math.min(
    insecureLinks.size * SCORING.insecure.perUrl,
    SCORING.insecure.max,
  );
  if (insecurePoints > 0) {
    findings.push(`Insecure HTTP links detected (${insecureLinks.size})`);
  }

  const lookalikeEntries = Array.from(lookalikeHosts.entries());
  const lookalikePoints = Math.min(
    lookalikeEntries.length * SCORING.lookalike.perHost,
    SCORING.lookalike.max,
  );
  if (lookalikePoints > 0) {
    const preview = lookalikeEntries
      .slice(0, 3)
      .map(([host, legit]) => `${host}≈${legit}`)
      .join(", ");
    findings.push(`Lookalike domains detected: ${preview}`);
  }
  if (mentionLookalikes.length > 0) {
    findings.push(`Suspicious domain mentions: ${mentionLookalikes.slice(0, 3).join(", ")}`);
  }

  const mismatchPoints = mismatchExamples.length ? SCORING.mismatch.points : 0;
  if (mismatchPoints > 0) {
    const sample = mismatchExamples[0];
    findings.push(`Display text vs href mismatch: ${sample.display} -> ${sample.href}`);
  }

  const linkPoints = Math.min(
    idnPoints + shortenerPoints + rawIpPoints + insecurePoints + mismatchPoints + lookalikePoints,
    50,
  );

  const urgencyFlag = URGENCY_RE.test(body);
  const credentialFlag = CREDENTIAL_RE.test(body);
  const contentRaw =
    (urgencyFlag ? SCORING.content.urgency : 0) +
    (credentialFlag ? SCORING.content.creds : 0);
  const contentPoints = Math.min(contentRaw, SCORING.content.max);
  if (urgencyFlag) findings.push("Urgency language detected");
  if (credentialFlag) findings.push("Credential/billing request language detected");

  const attachmentFlag = SUSPICIOUS_ATTACHMENT_RE.test(body);
  if (attachmentFlag) findings.push("Suspicious attachment type referenced");

  const fromDomain = parseHeaderDomain(headers, "From");//pulls out the From and Reply
  const replyDomain = parseHeaderDomain(headers, "Reply-To");
  const headerMismatch = fromDomain && replyDomain && fromDomain !== replyDomain;
  if (headerMismatch) {
    findings.push(`From (${fromDomain}) vs Reply-To (${replyDomain}) mismatch`);
  }

  const headerRaw =
    (attachmentFlag ? SCORING.header.attRef : 0) +
    (headerMismatch ? SCORING.header.replyMismatch : 0);
  const headerPoints = Math.min(headerRaw, SCORING.header.max);

  const totalScore = Math.max(
    0,
    Math.min(safeBrowsingPoints + linkPoints + contentPoints + headerPoints, 100),
  );

  return { score: totalScore, verdict: verdictFor(totalScore), findings };
} 
// ^^ sums Safe Browsing, link, content, and header points, clamps to 0–100, then calls verdictFor(totalScore) to map to “Likely Safe”, “Potentially Phishing”, “High Risk”, or “Known Dangerous”.
// The function returns score, verdict, findings, which the webhook stores in Firestore and returns to clients.


// Secret To access the function for analysis of forwarded emails
// firebase functions:secrets:set PHISH_SECRET
export const analyzeWebhook = onRequest(
  { maxInstances: 10, secrets: ["PHISH_SECRET", "SAFE_BROWSING_API_KEY"] },
  async (req: Request, res: Response): Promise<void> => {
    if (req.method !== "POST") { res.status(405).send("Use POST"); return; }

    const secret = req.get("x-analyze-secret") || "";
    const expected = process.env.PHISH_SECRET || "";   // now populated at runtime
    if (!expected || secret !== expected) { res.status(401).send("Unauthorized"); return; }            // per-function override (optional)

    const { subject = "", headers = "", body = "", sender = "", forwardedFrom = "", links = [] } = (req.body || {});
    const result = await analyzeEmailLogic({ subject, headers, body, links });

    await admin.firestore().collection("scans").add({
      subject,
      sender,
      forwardedFrom,
      bodyPreview: (body || "").slice(0, 1000),
      score: result.score,
      verdict: result.verdict,
      findings: result.findings,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json(result);   // do not return this!
    return;             // ensure Promise<void>
  }
);
