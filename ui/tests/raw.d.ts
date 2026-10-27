// Vite's `?raw` suffix imports a file's text; the tests read the legacy
// page's adapter this way to run it as the page does.
declare module "*?raw" {
  const text: string;
  export default text;
}
