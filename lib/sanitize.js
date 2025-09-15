function clampString(s, max = 2000) {
  return String(s ?? '').slice(0, max);
}

function escapeHTML(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}

function sanitizeText(s, max = 2000) {
  return escapeHTML(clampString(s, max)).trim();
}

module.exports = { clampString, escapeHTML, sanitizeText };
