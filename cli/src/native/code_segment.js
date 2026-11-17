// Structural accessible labels only; never inspect a private value or page text
// for code digits. Require every member's ordinal and total in document order.
function semanticSegmentIndex(el, count) {
    if (!['text', 'tel', 'number', 'password'].includes(el.type)) return null;
    const doc = el.ownerDocument;
    const labelled = (el.getAttribute('aria-labelledby') || '').trim();
    const label = labelled ? labelled.split(/\s+/).map(id => doc.getElementById(id)?.textContent || '').join(' ') :
        el.getAttribute('aria-label') || Array.from(el.labels || [], l => l.textContent).join(' ');
    const match = /^\s*(?:digit|code character)\s*(\d+)\s*of\s*(\d+)\s*$/i.exec(label);
    if (!match || Number(match[2]) !== count || Number(match[1]) < 1 || Number(match[1]) > count) return null;
    return Number(match[1]);
}
