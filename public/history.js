import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-app.js";
import { getFirestore, collection, query, orderBy, limit, getDocs } from "https://www.gstatic.com/firebasejs/11.0.1/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyDfxJ79kvn82UQc7z4Bkgzxf2zO31du6kk",
  authDomain: "email-scanner-5ff74.firebaseapp.com",
  projectId: "email-scanner-5ff74",
  storageBucket: "email-scanner-5ff74.appspot.com",
  messagingSenderId: "263168642490",
  appId: "1:263168642490:web:b21f3246000f9571ab6183",
  measurementId: "G-ZGSLS1F9QF",
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

const listEl = document.getElementById("historyList");
const statsEl = document.getElementById("historyStats");
const senderInput = document.getElementById("filterSender");
const scoreSelect = document.getElementById("filterScore");
const dateFromInput = document.getElementById("filterDateFrom");
const dateToInput = document.getElementById("filterDateTo");
const clearBtn = document.getElementById("clearFiltersBtn");

const SCORE_BANDS = {
  safe: { min: 0, max: 24 },
  suspect: { min: 25, max: 49 },
  high: { min: 50, max: 74 },
  danger: { min: 75, max: 100 },
};

const filters = {
  sender: "",
  score: "all",
  dateFrom: "",
  dateTo: "",
};

let scans = [];

listEl.innerHTML = "Loading…";

(async () => {
  try {
    const q = query(collection(db, "scans"), orderBy("createdAt", "desc"), limit(200));
    const snap = await getDocs(q);

    if (snap.empty) {
      listEl.textContent = "No scans yet.";
      statsEl.textContent = "";
      return;
    }

    scans = snap.docs.map((doc) => normalizeRecord(doc.id, doc.data()));
    applyFilters();
  } catch (e) {
    console.error(e);
    listEl.textContent = "Failed to load history.";
    statsEl.textContent = "";
  }
})();

senderInput?.addEventListener("input", () => {
  filters.sender = senderInput.value.trim().toLowerCase();
  applyFilters();
});
scoreSelect?.addEventListener("change", () => {
  filters.score = scoreSelect.value;
  applyFilters();
});
dateFromInput?.addEventListener("change", () => {
  filters.dateFrom = dateFromInput.value;
  applyFilters();
});
dateToInput?.addEventListener("change", () => {
  filters.dateTo = dateToInput.value;
  applyFilters();
});
clearBtn?.addEventListener("click", () => {
  senderInput.value = "";
  scoreSelect.value = "all";
  dateFromInput.value = "";
  dateToInput.value = "";
  filters.sender = "";
  filters.score = "all";
  filters.dateFrom = "";
  filters.dateTo = "";
  applyFilters();
});

function applyFilters() {
  if (!scans.length) return;
  const fromDate = parseDate(filters.dateFrom, false);
  const toDate = parseDate(filters.dateTo, true);

  const filtered = scans.filter((scan) => {
    const sender = (scan.sender || "").toLowerCase();
    const forwarded = (scan.forwardedFrom || "").toLowerCase();
    if (filters.sender && !sender.includes(filters.sender) && !forwarded.includes(filters.sender)) {
      return false;
    }
    if (filters.score !== "all" && !matchesScore(scan.score ?? 0, filters.score)) {
      return false;
    }
    const referenceDate = scan.originalDate ?? scan.createdAt;
    if (fromDate && (!referenceDate || referenceDate < fromDate)) return false;
    if (toDate && (!referenceDate || referenceDate > toDate)) return false;
    return true;
  });

  renderList(filtered);
  statsEl.textContent = `Showing ${filtered.length} of ${scans.length} scans`;
}

function renderList(records) {
  listEl.innerHTML = "";
  if (!records.length) {
    listEl.textContent = "No scans match your filters.";
    return;
  }

  const frag = document.createDocumentFragment();
  records.forEach((d) => {
    const card = document.createElement("div");
    card.className = "history-card";
    const verdictClass =
      d.verdict === "Known Dangerous" ? "verdict-high" :
      d.verdict === "High Risk" ? "verdict-high" :
      d.verdict === "Potentially Phishing" ? "verdict-suspicious" :
      "verdict-safe";

    const originalDate = formatDate(d.originalDate);
    const createdDate = formatDate(d.createdAt);
    const bodyPreview = (d.bodyPreview || "").slice(0, 1000);
    const findingsList = Array.isArray(d.findings) ? d.findings : [];
    const links = Array.isArray(d.links) ? d.links : [];

    card.innerHTML = `
      <div class="history-header" style="gap:8px;">
        <div>
          <div style="font-weight:700; font-size:1rem;">${escapeHtml(d.subject || "(no subject)")}</div>
          <div class="history-meta">
            <span>From: ${escapeHtml(d.sender || "(unknown)")}</span>
            ${d.forwardedFrom ? `<span>Forwarded: ${escapeHtml(d.forwardedFrom)}</span>` : ""}
          </div>
        </div>
        <div class="verdict-pill ${verdictClass}">${escapeHtml(d.verdict || "Unknown")} (${d.score ?? "?"}/100)</div>
      </div>
      <div class="history-meta">
        <span>Original: ${originalDate}</span>
        <span>Received: ${createdDate}</span>
      </div>
      <pre>${escapeHtml(bodyPreview)}${(d.bodyPreview || "").length > bodyPreview.length ? "…" : ""}</pre>
      ${
        links.length
          ? `<div><strong>Links:</strong><ul class="history-findings">${links
              .slice(0, 5)
              .map((link) => `<li><a href="${link}" target="_blank" rel="noopener">${escapeHtml(link)}</a></li>`)
              .join("")}${links.length > 5 ? `<li>+${links.length - 5} more</li>` : ""}</ul></div>`
          : ""
      }
      ${
        findingsList.length
          ? `<div><strong>Findings:</strong><ul class="history-findings">${findingsList
              .map((f) => `<li>${escapeHtml(String(f))}</li>`)
              .join("")}</ul></div>`
          : ""
      }
    `;
    frag.appendChild(card);
  });
  listEl.appendChild(frag);
}

function normalizeRecord(id, data) {
  return {
    id,
    ...data,
    createdAt: coerceDate(data.createdAt),
    originalDate: coerceDate(data.originalDate || data.origDate || data.forwardedDate),
  };
}

function coerceDate(value) {
  if (!value) return null;
  if (typeof value.toDate === "function") return value.toDate();
  if (typeof value === "number") return new Date(value);
  if (value?._seconds) return new Date(value._seconds * 1000);
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function parseDate(value, endOfDay) {
  if (!value) return null;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return null;
  if (endOfDay) dt.setHours(23, 59, 59, 999);
  else dt.setHours(0, 0, 0, 0);
  return dt;
}

function matchesScore(score, bandKey) {
  const band = SCORE_BANDS[bandKey];
  if (!band) return true;
  return score >= band.min && score <= band.max;
}

function formatDate(date) {
  return date ? date.toLocaleString() : "(unknown)";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
