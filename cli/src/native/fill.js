async function(value, route) {
    // A role (including combobox) does not make a wrapper editable. Never fall
    // back to Input.insertText: that edits whichever field still has focus.
    if (!this.isConnected) return { status: 'target_detached' };
    const input = this.tagName === 'INPUT';
    const textarea = this.tagName === 'TEXTAREA';
    const contenteditable = !input && !textarea && this.isContentEditable;
    const inputTypes = ['text', 'search', 'email', 'url', 'tel', 'password', 'number', 'date', 'datetime-local', 'time', 'month', 'week'];
    if ((!input && !textarea && !contenteditable) || (input && !inputTypes.includes(this.type)) ||
        this.matches(':disabled') || this.readOnly || this.closest('[inert]') ||
        this.getAttribute('aria-disabled') === 'true' || this.getAttribute('aria-readonly') === 'true') {
        return { status: 'not_editable' };
    }
    if (route === 'bound-form' && contenteditable) return { status: 'not_editable' };
    const doc = this.ownerDocument, view = doc.defaultView;
    let expected = value;
    if (!contenteditable) {
        const probe = doc.createElement(input ? 'input' : 'textarea');
        if (input) probe.type = this.type;
        probe.value = value;
        if (value && !probe.value) return { status: 'invalid_value' };
        expected = probe.value;
    }
    // Focus listeners can detach the old target or redirect focus. Check after
    // they have run, in the same synchronous call as the edit.
    this.focus();
    if (!this.isConnected) return { status: 'target_detached' };
    if (this.getRootNode().activeElement !== this) return { status: 'focus_changed' };
    if (contenteditable) {
        const selection = this.getRootNode().getSelection?.() || doc.getSelection();
        if (!selection) return { status: 'focus_changed' };
        const range = doc.createRange();
        range.selectNodeContents(this);
        selection.removeAllRanges();
        selection.addRange(range);
        if (!this.isConnected) return { status: 'target_detached' };
        if (this.getRootNode().activeElement !== this ||
            !this.contains(selection.anchorNode) || !this.contains(selection.focusNode)) {
            return { status: 'focus_changed' };
        }
        // The selection is scoped to this editor. Native editing preserves the
        // input events used by rich-text editors without a page-level CDP race.
        if (!doc.execCommand(value === '' ? 'delete' : 'insertText', false, value)) {
            return { status: 'value_not_retained' };
        }
    } else {
        const nativeText = textarea || ['text', 'search', 'email', 'url', 'tel', 'password'].includes(this.type);
        if (nativeText) {
            // The value setter plus a synthetic Event('input') leaves the DOM
            // changed without a browser edit. Phone/masked controls can ignore
            // it even while the value remains visible. Select only this control
            // and edit synchronously so Chrome emits its real InputEvent and
            // updates framework value tracking, just as for contenteditable.
            this.select();
            if (!this.isConnected) return { status: 'target_detached' };
            if (this.getRootNode().activeElement !== this) return { status: 'focus_changed' };
            // No CDP keyboard fallback: selection/focus and the actual edit must
            // stay in one call, or a different field could receive the text.
            if (!doc.execCommand(expected === '' ? 'delete' : 'insertText', false, expected)) {
                return { status: 'value_not_retained' };
            }
        } else {
            // Number and temporal controls do not expose a text selection.
            const prototype = view.HTMLInputElement.prototype;
            Object.getOwnPropertyDescriptor(prototype, 'value').set.call(this, expected);
            this.dispatchEvent(new view.InputEvent('input', { bubbles: true, composed: true,
                inputType: expected === '' ? 'deleteContentBackward' : 'insertReplacementText',
                data: expected === '' ? null : expected }));
        }
        this.dispatchEvent(new view.Event('change', { bubbles: true }));
    }
    const temporal = input && ['date', 'datetime-local', 'time', 'month', 'week'].includes(this.type);
    // Temporal and protected form edits retain their rendering barrier. Ordinary
    // text waits a task for application validators, including in background tabs.
    if (temporal || route === 'bound-form' || value === '') {
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
    } else {
        await new Promise(resolve => view.setTimeout(resolve, 0));
    }
    if (!this.isConnected) return { status: 'target_detached' };
    // Chrome leaves a caret placeholder <br> after deleting an editor's last
    // character. Its innerText is a newline even though no text remains.
    const actual = contenteditable ? (expected === '' && this.textContent === '' ? '' : this.innerText) : this.value;
    if (actual !== expected) return { status: 'value_not_retained' };
    return { status: 'filled' };
}
