//copy button
function legacyCopyFromInput(inputEl) {
  const wasReadOnly = inputEl.readOnly;
  inputEl.readOnly = false;
  inputEl.select();
  inputEl.setSelectionRange(0, 99999);
  const ok = document.execCommand('copy');
  inputEl.readOnly = wasReadOnly;
  window.getSelection().removeAllRanges();
  return ok;
}

async function copyForwardAddress() {
  const input = document.getElementById("forwardAddr");
  const val = input?.value || "";
  if (!val) return alert("No address to copy.");

  try {
    await navigator.clipboard.writeText(val);
    alert("Copied: " + val);
  } catch (_) {
    const ok = legacyCopyFromInput(input);
    if (ok) alert("Copied: " + val);
    else alert("Copy failed. Select the text and press Ctrl/Cmd+C.");
  }
}

//scoring
const analyzeBtn = document.getElementById("analyzeBtn");
const emailBodyEl = document.getElementById("emailBody");
const rawHeadersEl = document.getElementById("rawHeaders");

// UI
const detailsCard = document.getElementById("detailsCard");
const scoringCard = document.getElementById("scoringCard");
const outFrom = document.getElementById("outFrom");
const outSubject = document.getElementById("outSubject");
const outPreview = document.getElementById("outPreview");
const scoreCircle = document.getElementById("scoreCircle");
const scoreBar = document.getElementById("scoreBar");
const verdictText = document.getElementById("verdictText");
const breakdownList = document.getElementById("breakdownList");

document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("copyBtn");
  if (btn) btn.addEventListener("click", copyForwardAddress);
});

function extractUrls(text) {
  const urls = new Set();
  const urlRegex = /((https?:\/\/)?[a-z0-9\-\.]+\.[a-z]{2,}(?:[:0-9]*)?(?:\/[^\s<>"']*)?)/ig;
  let m;
  while ((m = urlRegex.exec(text)) !== null) {
    let u = m[1];
    if (!/^https?:\/\//i.test(u)) u = "http://" + u;
    try { urls.add((new URL(u)).toString()); } catch {}
  }
  return Array.from(urls);
}
function hostOf(url) { try { return new URL(url).host; } catch { return ""; } }
function hasPunycodeOrUnicode(host) {
  if (!host) return false;
  if (host.includes("xn--")) return true;
  return /[^\x00-\x7F]/.test(host);
}
function findDisplayHrefMismatches(text) {
  const findings = [];
  const md = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/ig;
  let m;
  while ((m = md.exec(text)) !== null) {
    const display = m[1], href = m[2];
    const dispHostMatch = display.match(/https?:\/\/([^\/\s]+)/i);
    const dispHost = dispHostMatch ? dispHostMatch[1] : (display.match(/([a-z0-9\-]+\.[a-z]{2,})/i) || [])[1];
    try {
      const hrefHost = new URL(href).host;
      if (dispHost && hrefHost && dispHost.toLowerCase() !== hrefHost.toLowerCase())
        findings.push({display:dispHost, href, hrefHost});
    } catch {}
  }
  const aTag = /<a[^>]*href="(https?:\/\/[^"]+)"[^>]*>(.*?)<\/a>/ig;
  while ((m = aTag.exec(text)) !== null) {
    const href = m[1], display = m[2].replace(/<[^>]+>/g,"");
    const dispHostMatch = display.match(/https?:\/\/([^\/\s]+)/i);
    const dispHost = dispHostMatch ? dispHostMatch[1] : (display.match(/([a-z0-9\-]+\.[a-z]{2,})/i) || [])[1];
    try {
      const hrefHost = new URL(href).host;
      if (dispHost && hrefHost && dispHost.toLowerCase() !== hrefHost.toLowerCase())
        findings.push({display:dispHost, href, hrefHost});
    } catch {}
  }
  return findings;
}
function parseHeaderDomain(headersText, headerName) {
  const re = new RegExp("^" + headerName + ":\\s*(.*)$", "im");
  const m = re.exec(headersText || "");
  if (!m) return "";
  const val = m[1];
  const emailMatch = val.match(/<(.+?)>/);
  const email = emailMatch ? emailMatch[1] : (val.match(/([a-z0-9.\-_+]+@[a-z0-9.\-]+\.[a-z]{2,})/i) || [])[1];
  if (!email) return "";
  return email.split("@")[1].toLowerCase();
}

analyzeBtn.addEventListener("click", () => {
  const body = (emailBodyEl.value || "").trim();
  const headers = (rawHeadersEl.value || "").trim();

  outFrom.textContent = "(unknown)";
  outSubject.textContent = "(none)";
  outPreview.textContent = body.slice(0, 800) || "(empty)";

  let score = 0;
  const breakdown = [];

  const urls = extractUrls(body);
  if (urls.length > 0) breakdown.push({msg: `Found ${urls.length} link(s)`, points: 0});
  urls.forEach(u => {
    const h = hostOf(u);
    if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|ow\.ly|cutt\.ly|rebrand\.ly/i.test(h)) { score += 15; breakdown.push({msg:`Shortener: ${h}`, points:15}); }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { score += 20; breakdown.push({msg:`Raw IP link: ${h}`, points:20}); }
    if (u.startsWith("http://")) { score += 10; breakdown.push({msg:`Insecure (http): ${u}`, points:10}); }
    if (hasPunycodeOrUnicode(h)) { score += 20; breakdown.push({msg:`Punycode/unicode host: ${h}`, points:20}); }
  });

  const mismatches = findDisplayHrefMismatches(body);
  if (mismatches.length) {
    score += 15;
    mismatches.slice(0,3).forEach(m => breakdown.push({msg:`Link text mismatch: text=${m.display} href=${m.href}`, points:0}));
    breakdown.push({msg:`Display/href mismatch present`, points:15});
  }

  const urgencyRe = /\b(urgent|immediately|action required|verify your account|your account will be|suspend(ed)?|payment required)\b/i;
  const credRe = /\b(login|sign in|enter your password|reset your password|confirm your identity|update billing)\b/i;
  if (urgencyRe.test(body)) { score += 15; breakdown.push({msg:"Urgency keywords", points:15}); }
  if (credRe.test(body)) { score += 20; breakdown.push({msg:"Credential/billing request keywords", points:20}); }

  if (/\.(?:exe|scr|js|jar|iso|img|zip|rar)\b/i.test(body)) { score += 25; breakdown.push({msg:"Suspicious attachment type mentioned", points:25}); }

  if (headers) {
    const fromDomain = parseHeaderDomain(headers, "From");
    const replyDomain = parseHeaderDomain(headers, "Reply-To");
    if (fromDomain) outFrom.textContent = fromDomain;
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      score += 20; breakdown.push({msg:`From (${fromDomain}) vs Reply-To (${replyDomain}) mismatch`, points:20});
    }
  }

  if (score < 0) score = 0;
  if (score > 100) score = 100;
  let verdict = "Likely Safe";
  let verdictClass = "verdict-safe";
  if (score >= 50) { verdict = "High Risk"; verdictClass = "verdict-high"; }
  else if (score >= 25) { verdict = "Potentially Phishing"; verdictClass = "verdict-suspicious"; }

  scoreCircle.textContent = score;
  scoreBar.style.width = Math.min(100, score) + "%";
  if (verdictClass === "verdict-safe") { scoreBar.style.background = "#2e7d32"; scoreCircle.style.background = "#2e7d32"; }
  else if (verdictClass === "verdict-suspicious") { scoreBar.style.background = "#d47f00"; scoreCircle.style.background = "#d47f00"; }
  else { scoreBar.style.background = "#b00020"; scoreCircle.style.background = "#b00020"; }

  verdictText.textContent = `Verdict: ${verdict} — Score ${score}/100`;
  verdictText.className = verdictClass;

  breakdownList.innerHTML = "";
  if (breakdown.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No obvious rules matched — result is heuristic.";
    breakdownList.appendChild(li);
  } else {
    breakdown.forEach(b => {
      const li = document.createElement("li");
      li.textContent = `${b.msg}${b.points ? ` (+${b.points})` : ""}`;
      breakdownList.appendChild(li);
    });
  }

  detailsCard.classList.remove("hidden");
  scoringCard.classList.remove("hidden");
  scoringCard.scrollIntoView({behavior:"smooth"});
});
