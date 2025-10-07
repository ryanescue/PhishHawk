// // Import the functions you need from the SDKs you need
// import { initializeApp } from "firebase/app";
// import { getFunctions, httpsCallable } from "firebase/functions";
// import { getAnalytics } from "firebase/analytics";
// // TODO: Add SDKs for Firebase products that you want to use
// // https://firebase.google.com/docs/web/setup#available-libraries

// // Your web app's Firebase configuration
// // For Firebase JS SDK v7.20.0 and later, measurementId is optional
// const firebaseConfig = {
//   apiKey: "AIzaSyDfxJ79kvn82UQc7z4Bkgzxf2zO31du6kk",
//   authDomain: "email-scanner-5ff74.firebaseapp.com",
//   projectId: "email-scanner-5ff74",
//   storageBucket: "email-scanner-5ff74.firebasestorage.app",
//   messagingSenderId: "263168642490",
//   appId: "1:263168642490:web:b21f3246000f9571ab6183",
//   measurementId: "G-ZGSLS1F9QF"
// };

// // Initialize Firebase
// const app = initializeApp(firebaseConfig);
// const analytics = getAnalytics(app);
// const functions = getFunctions(app);

// // hook up button
// document.getElementById("scanBtn").addEventListener("click", async () => {
//   const body = document.getElementById("emailBody").value;
//   const analyzeEmail = httpsCallable(functions, "analyzeEmail");
//   const res = await analyzeEmail({ body });
//   document.getElementById("result").textContent = JSON.stringify(res.data, null, 2);
// });

//Had to remove firebase connection at the moment
const analyzeBtn = document.getElementById("analyzeBtn");
const emailBodyEl = document.getElementById("emailBody");
const rawHeadersEl = document.getElementById("rawHeaders");

//UI
const detailsCard= document.getElementById("detailsCard");
const scoringCard= document.getElementById("scoringCard");
const outFrom =document.getElementById("outFrom");
const outSubject= document.getElementById("outSubject");
const outPreview= document.getElementById("outPreview");
const scoreCircle= document.getElementById("scoreCircle");
const scoreBar= document.getElementById("scoreBar");
const verdictText= document.getElementById("verdictText");
const breakdownList= document.getElementById("breakdownList");

//copy button
document.getElementById("copyBtn").addEventListener("click", async () => {
  const val = document.getElementById("forwardAddr").value;
  try { await navigator.clipboard.writeText(val); alert("Copied: " + val); }
  catch { alert("Copy failed. Select and press Ctrl/Cmd+C."); }
});

//helper function to extract URLs
function extractUrls(text) {
  const urls = new Set();
  const urlRegex = /((https?:\/\/)?[a-z0-9\-\.]+\.[a-z]{2,}(?:[:0-9]*)?(?:\/[^\s<>"']*)?)/ig;
  let m;
  while ((m = urlRegex.exec(text)) !== null) {
    let u = m[1];
    if (!/^https?:\/\//i.test(u)) u = "http://" + u;
    try { urls.add((new URL(u)).toString()); } catch(e) {}
  }
  return Array.from(urls);
}

//helper function to parse host
function hostOf(url) {
  try {return new URL(url).host;} catch {return "";}
}

//helper function to check for punycode/unicode
function hasPunycodeOrUnicode(host) {
  if (!host) return false;
  if (host.includes("xn--")) return true;
  return /[^\x00-\x7F]/.test(host);
}

// helper: find display vs href mismatches (markdown & simple <a> patterns)
function findDisplayHrefMismatches(text) {
  const findings=[];
  // markdown [label](url)
  const md=/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/ig;
  let m;
  while ((m = md.exec(text)) !== null) {
    const display= m[1], href = m[2];
    const dispHostMatch=display.match(/https?:\/\/([^\/\s]+)/i);
    const dispHost= dispHostMatch ? dispHostMatch[1]:(display.match(/([a-z0-9\-]+\.[a-z]{2,})/i) || [])[1];
    try {
      const hrefHost=new URL(href).host;
      if (dispHost && hrefHost && dispHost.toLowerCase() !== hrefHost.toLowerCase()) findings.push({display:dispHost, href, hrefHost});
    } catch {}
  }
  // <a href="...">link text</a>
  const aTag = /<a[^>]*href="(https?:\/\/[^"]+)"[^>]*>(.*?)<\/a>/ig;
  while ((m = aTag.exec(text)) !== null) {
    const href = m[1], display = m[2].replace(/<[^>]+>/g,"");
    const dispHostMatch = display.match(/https?:\/\/([^\/\s]+)/i);
    const dispHost = dispHostMatch ? dispHostMatch[1] : (display.match(/([a-z0-9\-]+\.[a-z]{2,})/i) || [])[1];
    try {
      const hrefHost = new URL(href).host;
      if (dispHost && hrefHost && dispHost.toLowerCase() !== hrefHost.toLowerCase()) findings.push({display:dispHost, href, hrefHost});
    } catch {}
  }
  return findings;
}

// parsing from and reply-To from raw headers
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
  // fill details area
  outFrom.textContent = "(unknown)";
  outSubject.textContent = "(none)";
  outPreview.textContent = body.slice(0, 800) || "(empty)";
  // scoring rules & weights
  let score = 0;
  const breakdown = [];

  //chescking links
  const urls = extractUrls(body);
  if (urls.length > 0) {
    breakdown.push({msg: `Found ${urls.length} link(s)`, points: 0});
  }
  urls.forEach(u => {
    const h = hostOf(u);
    if (/bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|ow\.ly|cutt\.ly|rebrand\.ly/i.test(h)) {
      score += 15; breakdown.push({msg:`Shortener: ${h}`, points:15});}
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { score += 20; breakdown.push({msg:`Raw IP link: ${h}`, points:20}); }
    if (u.startsWith("http://")) { score += 10; breakdown.push({msg:`Insecure (http): ${u}`, points:10}); }
    if (hasPunycodeOrUnicode(h)) { score += 20; breakdown.push({msg:`Punycode/unicode host: ${h}`, points:20}); }
  });

  //display vs href mismatches
  const mismatches = findDisplayHrefMismatches(body);
  if (mismatches.length) {
    score += 15;
    mismatches.slice(0,3).forEach(m => breakdown.push({msg:`Link text mismatch: text=${m.display} href=${m.href}`, points:0}));
    breakdown.push({msg:`Display/href mismatch present`, points:15});
  }

  //keyword checks
  const urgencyRe = /\b(urgent|immediately|action required|verify your account|your account will be|suspend(ed)?|payment required)\b/i;
  const credRe = /\b(login|sign in|enter your password|reset your password|confirm your identity|update billing)\b/i;
  if (urgencyRe.test(body)) { score += 15; breakdown.push({msg:"Urgency keywords", points:15}); }
  if (credRe.test(body)) { score += 20; breakdown.push({msg:"Credential/billing request keywords", points:20}); }

  //attachments
  if (/\.(?:exe|scr|js|jar|iso|img|zip|rar)\b/i.test(body)) { score += 25; breakdown.push({msg:"Suspicious attachment type mentioned", points:25}); }

  //headers checks this is optional
  if (headers) {
    const fromDomain = parseHeaderDomain(headers, "From");
    const replyDomain = parseHeaderDomain(headers, "Reply-To");
    if (fromDomain) outFrom.textContent = fromDomain;
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      score += 20; breakdown.push({msg:`From (${fromDomain}) vs Reply-To (${replyDomain}) mismatch`, points:20});
    }
  }

  // clamp score to 0..100
  //havent implemented a scoring card yet
  if (score < 0) score = 0;
  if (score > 100) score = 100;
  let verdict = "Likely Safe";
  let verdictClass = "verdict-safe";
  if (score >= 50) { verdict = "High Risk"; verdictClass = "verdict-high"; }
  else if (score >= 25) { verdict = "Potentially Phishing"; verdictClass = "verdict-suspicious"; }

  //scoring UI
  scoreCircle.textContent = score;
  scoreBar.style.width = Math.min(100, score) + "%";
  if (verdictClass === "verdict-safe") { scoreBar.style.background = "#2e7d32"; scoreCircle.style.background = "#2e7d32"; }
  else if (verdictClass === "verdict-suspicious") { scoreBar.style.background = "#d47f00"; scoreCircle.style.background = "#d47f00"; }
  else { scoreBar.style.background = "#b00020"; scoreCircle.style.background = "#b00020"; }

  verdictText.textContent = `Verdict: ${verdict} — Score ${score}/100`;
  verdictText.className = verdictClass;

  breakdownList.innerHTML = "";
  if (breakdown.length===0) {
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
