// Shared structural identities for renderer projections and the pierced CDP tree.
// The shadow separator is an identity component, not a CSS selector.
const shadowParent = el => el.parentElement || el.getRootNode()?.host || null;
// Each projection runs synchronously. Cache only for this invocation: no page
// mutation can invalidate these positions, and nothing survives to another read.
const shadowPaths = new WeakMap();
const shadowPositions = new WeakMap();
const shadowIndex = el => {
    if (!shadowPositions.has(el)) {
        let index = 1;
        for (const sibling of el.parentNode?.children || [el])
            shadowPositions.set(sibling, index++);
    }
    return shadowPositions.get(el);
};
const shadowPath = el => {
    const pending = [];
    while (el && !shadowPaths.has(el)) {
        pending.push(el);
        el = shadowParent(el);
    }
    let path = el ? shadowPaths.get(el) : '';
    for (let i = pending.length - 1; i >= 0; i--) {
        const node = pending[i];
        if (path) path += node.parentElement ? ' > ' : ' >>> ';
        path += '*:nth-child(' + shadowIndex(node) + ')';
        shadowPaths.set(node, path);
    }
    return path;
};
function* shadowElements(root) {
    for (const el of root.querySelectorAll('*')) {
        yield el;
        if (el.shadowRoot) yield* shadowElements(el.shadowRoot);
    }
}
