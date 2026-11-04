// Shared structural identities for renderer projections and the pierced CDP tree.
// The shadow separator is an identity component, not a CSS selector.
const shadowParent = el => el.parentElement || el.getRootNode()?.host || null;
const shadowPath = el => {
    const parts = [];
    while (el) {
        let index = 1;
        for (let p = el.previousElementSibling; p; p = p.previousElementSibling) index++;
        parts.unshift('*:nth-child(' + index + ')');
        if (el.parentElement) {
            parts.unshift(' > ');
            el = el.parentElement;
        } else {
            el = el.getRootNode()?.host || null;
            if (el) parts.unshift(' >>> ');
        }
    }
    return parts.join('');
};
function* shadowElements(root) {
    for (const el of root.querySelectorAll('*')) {
        yield el;
        if (el.shadowRoot) yield* shadowElements(el.shadowRoot);
    }
}
