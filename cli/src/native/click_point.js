function() {
    const doc = this.ownerDocument, win = doc && doc.defaultView;
    // Framed targets retain CDP box-model conversion, including cross-origin
    // same-process frame offsets. In the top document DOM and input coordinates
    // are both viewport CSS pixels, so no remote anchor/conversion is needed.
    const enabled = () => (CLICK_GUARD)(this);
    let error = enabled();
    if (error) return {error};
    if (!win || win !== win.top) return {framed:true};
    const checkbox = CHECKBOX_POINT;
    let point = checkbox.call(this);
    if (point && point.error) return {error:'not_hittable'};
    if (!point) {
        this.scrollIntoView({block:'center',inline:'center',behavior:'instant'});
        const r = this.getBoundingClientRect();
        if (!(r.width > 0 && r.height > 0)) return {error:'not_hittable'};
        const l=Math.max(0,r.left), t=Math.max(0,r.top);
        const rr=Math.min(win.innerWidth,r.right), b=Math.min(win.innerHeight,r.bottom);
        if (!(rr > l && b > t)) return {error:'not_hittable'};
        point = {x:(l+rr)/2, y:(t+b)/2};
    }
    error = enabled();
    if (error) return {error};
    const blockerAt = BLOCKER_AT;
    const blocker = blockerAt(doc, this, point.x, point.y);
    return blocker ? {blocker} : point;
}
