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
    // Ordinary edits (including clearing a rich editor) need application tasks,
    // not painted frames, which Chrome may suspend in background tabs. Keep the
    // existing two-frame barrier for temporal/protected form validators. The
    // command's deadline owns that wait; a second 100 ms deadline falsely fails
    // healthy but delayed frames. No edit is retried when the command expires.
    if (temporal || route === 'bound-form') {
        await new Promise(resolve => view.requestAnimationFrame(() => {
            view.requestAnimationFrame(() => view.setTimeout(resolve, 0));
        }));
    } else {
        await new Promise(resolve => view.setTimeout(resolve, 0));
    }
    if (!this.isConnected) return { status: 'target_detached' };
    // innerText is presentation text: adjacent <p> elements add two newlines,
    // while Quill/DraftJS plain text has one block separator. Serialize the DOM
    // blocks instead, preserving actual spaces, empty blocks and explicit breaks.
    // A final <br> in each block is Chrome's caret placeholder, not another line.
    const editorText = (container, block = true) => {
        const parts = [];
        let inline = '', hasInline = false, finalBreak = false;
        const flush = () => {
            if (hasInline) parts.push(finalBreak && block ? inline.slice(0, -1) : inline);
            inline = ''; hasInline = false; finalBreak = false;
        };
        for (const node of container.childNodes) {
            if (node.nodeType === view.Node.TEXT_NODE) {
                if (node.data) { inline += node.data; hasInline = true; finalBreak = false; }
            } else if (node.nodeType === view.Node.ELEMENT_NODE) {
                const display = view.getComputedStyle(node).display;
                if (display === 'none') continue;
                if (node.tagName === 'BR') {
                    inline += '\n'; hasInline = true; finalBreak = true;
                } else if (['block', 'flow-root', 'list-item', 'flex', 'grid', 'table', 'table-row'].includes(display)) {
                    flush();
                    parts.push(editorText(node));
                } else {
                    const text = editorText(node, false);
                    if (text) { inline += text; hasInline = true; finalBreak = false; }
                }
            }
        }
        flush();
        return parts.join('\n');
    };
    const actual = contenteditable ? editorText(this) : this.value;
    // Chrome encodes edge spaces as NBSP to keep them visible. Accept that
    // encoding only where a space was requested; never trim or collapse text.
    const logical = contenteditable ? actual.split('').map((char, index) =>
        char === '\u00a0' && expected[index] === ' ' ? ' ' : char).join('') : actual;
    if (logical !== expected) return { status: 'value_not_retained' };
    return { status: 'filled' };
}
