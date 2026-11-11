function(expected) {
    const target = this, doc = target.ownerDocument, view = doc.defaultView;
    // Point resolution owns scrolling, frame coordinates, clipping and label
    // activation. Observe only: another scroll here would invalidate its point.
    const geometry = () => {
        if (!target.isConnected) return null;
        const nodes = [target, ...(target.labels || []), doc.documentElement];
        const values = [view.innerWidth, view.innerHeight, view.scrollX, view.scrollY];
        for (const node of nodes) {
            const r = node.getBoundingClientRect();
            values.push(r.left, r.top, r.width, r.height);
        }
        return values.every(Number.isFinite) ? values : null;
    };
    const equal = (a, b) => a && b && a.length === b.length
        && a.every((v, i) => Math.abs(v - b[i]) < 0.25);
    // Final validation is synchronous in the pinned object's own document.
    if (expected !== undefined) return !!equal(geometry(), expected);
    return new Promise(resolve => {
        let previous, stable = 0, sampleTimer;
        const finish = value => {
            view.clearTimeout(deadlineTimer);
            view.clearTimeout(sampleTimer);
            resolve(value);
        };
        const deadlineTimer = view.setTimeout(() => finish('unstable'), 2000);
        const sample = () => {
            const current = geometry();
            if (!current) return finish('detached');
            stable = equal(current, previous) ? stable + 1 : 0;
            previous = current;
            if (stable >= 2) return finish(current);
            // Background tabs can suspend animation frames indefinitely.
            sampleTimer = view.setTimeout(sample, 32);
        };
        sample();
    });
}
