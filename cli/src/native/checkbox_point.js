function() {
    const input = this;
    if (!input.matches('input[type="checkbox"], input[type="radio"]')) return null;
    const doc = input.ownerDocument;
    const win = doc.defaultView;
    const labels = Array.from(input.labels || []).filter(label => label.control === input);
    const candidates = [input, ...labels];
    const up = node => node.parentNode || node.host || null;
    const activates = hit => {
        // Descendants of the input are not meaningful, but shadow descendants
        // of a label can paint its styled checkbox. Do not click links or other
        // interactive descendants: their default action is not label activation.
        for (let node=hit; node; node=up(node)) {
            if (node === input) return true;
            if (labels.includes(node)) return true;
            if (node.nodeType === 1 && node.matches('a[href],button,input,select,textarea,[contenteditable]:not([contenteditable="false"]),[role="button"],[role="link"]')) return false;
        }
        return false;
    };
    const hitAt = (x,y) => {
        let hit = doc.elementFromPoint(x,y);
        while (hit && hit.shadowRoot) {
            const inner = hit.shadowRoot.elementFromPoint(x,y);
            if (!inner || inner === hit) break;
            hit = inner;
        }
        return hit;
    };
    const find = () => {
        for (const candidate of candidates) {
            const style = win.getComputedStyle(candidate);
            if (style.visibility !== 'visible' || style.display === 'none') continue;
            for (const rect of candidate.getClientRects()) {
                const left=Math.max(0,rect.left), top=Math.max(0,rect.top);
                const right=Math.min(win.innerWidth,rect.right), bottom=Math.min(win.innerHeight,rect.bottom);
                if (right <= left || bottom <= top) continue;
                for (const fx of [0.5,0.1,0.9]) for (const fy of [0.5,0.1,0.9]) {
                    const x=left+(right-left)*fx, y=top+(bottom-top)*fy;
                    if (activates(hitAt(x,y))) return {x,y};
                }
            }
        }
        return null;
    };
    let point = find();
    if (point) return point;
    // Scroll a painted associated label rather than moving the viewport to a
    // deliberately hidden input. Hit testing still proves actual activation.
    for (const candidate of [...labels,input]) {
        if (!candidate.getClientRects().length) continue;
        candidate.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
        point = find();
        if (point) return point;
    }
    return {error:'not_hittable'};
}
