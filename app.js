// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getFunctions, httpsCallable } from "firebase/functions";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyDfxJ79kvn82UQc7z4Bkgzxf2zO31du6kk",
  authDomain: "email-scanner-5ff74.firebaseapp.com",
  projectId: "email-scanner-5ff74",
  storageBucket: "email-scanner-5ff74.firebasestorage.app",
  messagingSenderId: "263168642490",
  appId: "1:263168642490:web:b21f3246000f9571ab6183",
  measurementId: "G-ZGSLS1F9QF"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);
const functions = getFunctions(app);

// Hook up button
document.getElementById("scanBtn").addEventListener("click", async () => {
  const body = document.getElementById("emailBody").value;
  const analyzeEmail = httpsCallable(functions, "analyzeEmail");
  const res = await analyzeEmail({ body });
  document.getElementById("result").textContent = JSON.stringify(res.data, null, 2);
});
