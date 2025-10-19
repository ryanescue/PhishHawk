import { setGlobalOptions } from "firebase-functions/v2";
import { onRequest } from "firebase-functions/v2/https";
import * as admin from "firebase-admin";
import type { Request, Response } from "express";

admin.initializeApp();
setGlobalOptions({ region: "us-central1", maxInstances: 10 });


//analyzer logic (same as before)
function analyzeEmailLogic(input: { subject?: string; headers?: string; body: string }) {
  const body = input.body || "";
  let score = 0;
  const findings: string[] = [];

  if (/bit\.ly|tinyurl|t\.co/i.test(body)) { score += 15; findings.push("Shortened URL"); }
  if (/http:\/\//i.test(body))           { score += 10; findings.push("Insecure link (HTTP)"); }
  if (/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(body)) { score += 20; findings.push("Raw IP link"); }
  if (/\b(urgent|verify your account|reset password|suspend)\b/i.test(body)) {
    score += 20; findings.push("Urgency/credential keywords");
  }

  let verdict: "Likely Safe" | "Potentially Phishing" | "High Risk" = "Likely Safe";
  if (score >= 50) verdict = "High Risk";
  else if (score >= 25) verdict = "Potentially Phishing";

  return { score, verdict, findings };
}

//Secret To access the function for anaylasis of forwarded emails
//firebase functions:secrets:set PHISH_SECRET
export const analyzeWebhook = onRequest(
  { maxInstances: 10, secrets: ["PHISH_SECRET"] },
  async (req: Request, res: Response): Promise<void> => {
    if (req.method !== "POST") { res.status(405).send("Use POST"); return; }

    const secret = req.get("x-analyze-secret") || "";
    const expected = process.env.PHISH_SECRET || "";   // now populated at runtime
    if (!expected || secret !== expected) { res.status(401).send("Unauthorized"); return; }            // per-function override (optional)

    const { subject = "", headers = "", body = "", sender = "", forwardedFrom = "" } = (req.body || {});
    const result = analyzeEmailLogic({ subject, headers, body });

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
