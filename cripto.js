// cripto.js — cifratura dei dati della dashboard. Usato dal browser (index.html) e dal Mac (cifra.mjs).
// AES-256-GCM con chiave da PBKDF2-SHA256. Il sale è fisso per sito, così il telefono può ricordare la chiave.
export const ITER = 600000;
const enc = new TextEncoder();
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export async function deriva(password, saltB64, iter = ITER) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: unb64(saltB64), iterations: iter },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function cifra(key, saltB64, testo, iter = ITER) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(testo)));
  let s = ""; // a pezzi: String.fromCharCode(...) su array grandi supera lo stack
  for (let i = 0; i < ct.length; i += 0x8000) s += String.fromCharCode(...ct.subarray(i, i + 0x8000));
  return { v: 1, salt: saltB64, iter, iv: b64(iv), ct: btoa(s) };
}

// Restituisce il testo in chiaro; lancia un errore se la chiave è sbagliata o i dati sono stati alterati.
export async function decifra(key, pacco) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(pacco.iv) }, key, unb64(pacco.ct));
  return new TextDecoder().decode(pt);
}
