// ---------------------------------------------------------------------------
// Shared HTML page chrome + escaping helpers.
//
// pageChrome holds the document skeleton common to every SSO page: doctype,
// <html lang="en">, charset meta, the <style> wrapper, and the <body> wrapper.
// The per-page CSS is intentionally NOT deduplicated here: a byte-level diff
// of the six historical <style> blocks showed that no two are identical
// (different font stacks, resets, max-widths, button shapes, and dynamic
// brand colors), so each view passes its own CSS verbatim to preserve
// byte-identical output.
// ---------------------------------------------------------------------------

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SCRIPT_STRING_ESCAPES: Record<string, string> = {
  '<': '\\u003c',
  '>': '\\u003e',
  '&': '\\u0026',
  "'": '\\u0027',
  '\u2028': '\\u2028',
  '\u2029': '\\u2029',
};

/**
 * A string as a JavaScript literal for an inline <script>: JSON, with the
 * characters that could end the script element or the string escaped.
 */
export function jsString(value: string): string {
  return JSON.stringify(value).replace(/[<>&'\u2028\u2029]/g, (c) => SCRIPT_STRING_ESCAPES[c] ?? c);
}

/** The opening tag of an inline script, carrying the response's CSP nonce. */
export function scriptOpen(nonce: string | undefined): string {
  return nonce ? `<script nonce="${escapeHtml(nonce)}">` : '<script>';
}

/** A branding colour, only in #rrggbb form; anything else gives the fallback. */
export function safeColor(value: string | undefined, fallback = '#ffffff'): string {
  return typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value) ? value : fallback;
}

export function isHttpsUrl(value: string | undefined): value is string {
  return typeof value === 'string' && value.toLowerCase().startsWith('https://');
}

export type PageChromeOptions = {
  /** Head lines rendered after `<meta charset>` and before `<style>` (viewport/referrer metas + title), exact bytes. */
  head: string;
  /** Full per-page CSS placed inside the `<style>` tag, exact bytes. */
  css: string;
};

export function pageChrome(bodyHtml: string, opts: PageChromeOptions): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
${opts.head}
  <style>
${opts.css}
  </style>
</head>
<body>
${bodyHtml}
</body>
</html>`;
}

/**
 * Page script: hand sign-in tokens to /callback in a POST body (a form
 * submission from this origin), never in a URL. Takes the fields to send;
 * empty values are left out.
 */
export const POST_TO_CALLBACK_SCRIPT = `    function postToCallback(fields) {
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = '/callback';
      for (const name of Object.keys(fields)) {
        const value = fields[name];
        if (!value) continue;
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
      }
      document.body.appendChild(form);
      form.submit();
    }`;
