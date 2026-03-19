// Firebase configuration
// REPLACE WITH YOUR ACTUAL CONFIGURATION FROM FIREBASE CONSOLE
const firebaseConfig = {
  apiKey: "AIzaSyDi5uvXy0qM1aH5xeGdYscg_azjrwl72OE",
  authDomain: "autored-7a93a.firebaseapp.com",
  projectId: "autored-7a93a",
  storageBucket: "autored-7a93a.firebasestorage.app",
  messagingSenderId: "60442726788",
  appId: "1:60442726788:web:f24ace86b22de795448dd1",
  measurementId: "G-M4ZXRX69K8"
}

// Import the functions you need from the SDKs you need
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, signInWithEmailAndPassword, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getFirestore, collection, query, where, onSnapshot, getDocs, addDoc, updateDoc, doc, serverTimestamp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

export { auth, db, signInWithEmailAndPassword, onAuthStateChanged, signOut, collection, query, where, onSnapshot, getDocs, addDoc, updateDoc, doc, serverTimestamp };
