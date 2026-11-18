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

export function jsString(value: string): string {
  return JSON.stringify(value);
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
