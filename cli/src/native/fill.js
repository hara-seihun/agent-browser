async function(value, route) {
    const input = this.tagName === 'INPUT';
    const textarea = this.tagName === 'TEXTAREA';
    const temporal = input && ['date', 'datetime-local', 'time', 'month', 'week'].includes(this.type);
    if (this.matches(':disabled') || this.readOnly) return { status: 'not_editable' };
    if (route === 'bound-form' && (!input && !textarea)) return { status: 'not_editable' };
    if (route !== 'bound-form' && !temporal && !(value === '' && (input || textarea))) return { status: 'keyboard_required' };
    const probe = this.ownerDocument.createElement(input ? 'input' : 'textarea');
    if (input) probe.type = this.type;
    probe.value = value;
    if (value && !probe.value) return { status: 'invalid_value' };
    const expected = probe.value;
    const view = this.ownerDocument.defaultView;
    const prototype = input ? view.HTMLInputElement.prototype : view.HTMLTextAreaElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(prototype, 'value').set;
    this.focus();
    setter.call(this, expected);
    this.dispatchEvent(new view.Event('input', { bubbles: true }));
    this.dispatchEvent(new view.Event('change', { bubbles: true }));
    // React commits and application validators can run after the
    // event's microtasks. Observe after rendering, not inside dispatch.
    const rendering = await new Promise(resolve => {
        let frame, secondFrame, task;
        let settled = false;
        const finish = status => {
            if (settled) return;
            settled = true;
            if (frame !== undefined) view.cancelAnimationFrame(frame);
            if (secondFrame !== undefined) view.cancelAnimationFrame(secondFrame);
            if (task !== undefined) view.clearTimeout(task);
            view.clearTimeout(deadline);
            resolve(status);
        };
        const deadline = view.setTimeout(() => finish('render_timeout'), 100);
        frame = view.requestAnimationFrame(() => {
            secondFrame = view.requestAnimationFrame(() => {
                task = view.setTimeout(() => finish('rendered'), 0);
            });
        });
    });
    if (rendering !== 'rendered') return { status: rendering };
    if (!this.isConnected) return { status: 'target_detached' };
    if (this.value !== expected) return { status: 'value_not_retained' };
    return { status: 'filled' };
}
