// Vite's `?raw` suffix imports a file as a string (used for the passphrase word list).
declare module "*?raw" {
  const text: string;
  export default text;
}
