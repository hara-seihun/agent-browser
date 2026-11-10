function() {
    const target = this;
    const view = target.ownerDocument.defaultView;
    // Scroll once without smooth scrolling. Never replay a pointer gesture.
    target.scrollIntoView({block: 'nearest', inline: 'nearest', behavior: 'instant'});
    return new Promise(resolve => {
        let previous;
        let stable = 0;
        let finished = false;
        const finish = value => {
            if (finished) return;
            finished = true;
            view.clearTimeout(timer);
            resolve(value);
        };
        // Background or frozen renderers must also settle within a finite budget.
        const timer = view.setTimeout(() => finish('unstable'), 2000);
        const sample = () => {
            if (finished) return;
            if (!target.isConnected) return finish('detached');
            const r = target.getBoundingClientRect();
            const geometry = [r.left, r.top, r.width, r.height];
            const centerX = r.left + r.width / 2;
            const centerY = r.top + r.height / 2;
            const valid = geometry.every(Number.isFinite) && r.width > 0 && r.height > 0
                && centerX >= 0 && centerX < view.innerWidth
                && centerY >= 0 && centerY < view.innerHeight;
            stable = valid && previous && geometry.every((v, i) => Math.abs(v - previous[i]) < 0.25)
                ? stable + 1 : 0;
            previous = geometry;
            if (stable >= 2) return finish(geometry);
            view.requestAnimationFrame(sample);
        };
        view.requestAnimationFrame(sample);
    });
}
