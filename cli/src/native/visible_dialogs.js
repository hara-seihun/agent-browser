function() {
    const doc = this;
    const win = doc.defaultView;
    const modalSelector = '[role="dialog"], [role="alertdialog"], dialog, [aria-modal="true"]';
    /* SHADOW_DOM_HELPERS */
    const path = shadowPath;
    const visible = el => {
        if (['SCRIPT', 'STYLE', 'TEMPLATE', 'NOSCRIPT'].includes(el.tagName)) return false;
        const css = win.getComputedStyle(el);
        if (css.display === 'none' || css.visibility !== 'visible' || Number(css.opacity) === 0
            || css.contentVisibility === 'hidden') return false;
        // display:contents has no box but may contain visible text and controls.
        return css.display === 'contents' || Array.from(el.getClientRects()).some(r => r.width > 0 && r.height > 0);
    };
    const rendered = el => {
        for (let p = el; p; p = shadowParent(p)) {
            const css = win.getComputedStyle(p);
            if (css.display === 'none' || css.visibility !== 'visible' || Number(css.opacity) === 0
                || css.contentVisibility === 'hidden') return false;
        }
        return visible(el);
    };
    const roleOf = el => {
        const explicit = el.getAttribute('role');
        if (explicit) return explicit;
        if (el.getAttribute('aria-modal') === 'true') return 'dialog';
        const tag = el.tagName;
        if (tag === 'DIALOG') return 'dialog';
        if (tag === 'BUTTON' || tag === 'SUMMARY') return 'button';
        if (tag === 'A' && el.hasAttribute('href')) return 'link';
        if (/^H[1-6]$/.test(tag)) return 'heading';
        if (tag === 'TEXTAREA' || el.isContentEditable) return 'textbox';
        if (tag === 'SELECT') return 'combobox';
        if (tag === 'OPTION') return 'option';
        if (tag === 'INPUT') {
            if (['button', 'submit', 'reset'].includes(el.type)) return 'button';
            if (['checkbox', 'radio'].includes(el.type)) return el.type;
            return 'textbox';
        }
        if (el.hasAttribute('onclick') || el.onclick || el.tabIndex >= 0) return 'button';
        return 'generic';
    };
    const dialogs = [];
    for (const root of shadowElements(doc)) {
        if (!root.matches(modalSelector)) continue;
        if (!rendered(root)) continue;
        // Each dialog is independent; Rust skips those already represented in AX.
        const nodes = [];
        const walk = (el, parent) => {
            if (!visible(el)) return;
            const index = nodes.length;
            const role = roleOf(el);
            const props = [];
            const add = (name, value) => props.push({name, value: {type: typeof value, value}});
            if (/^H[1-6]$/.test(el.tagName)) add('level', Number(el.tagName[1]));
            if (el.disabled) add('disabled', true);
            if (el.required) add('required', true);
            if (['checkbox', 'radio'].includes(role)) add('checked', String(el.indeterminate ? 'mixed' : el.checked));
            for (const [attr, name] of [['aria-expanded','expanded'], ['aria-invalid','invalid']])
                if (el.hasAttribute(attr)) add(name, el.getAttribute(attr));
            nodes.push({selector:path(el), parent, role, name:el.getAttribute('aria-label') || '', properties:props});
            for (const child of el.childNodes) {
                if (child.nodeType === 1) walk(child, index);
                else if (child.nodeType === 3 && child.textContent.trim()) {
                    // Associate direct text with its owning element so private control
                    // and exported-text protection still applies before aggregation.
                    nodes.push({selector:path(el), parent:index, role:'StaticText', name:child.textContent, properties:[]});
                }
            }
            if (el.shadowRoot) {
                for (const child of el.shadowRoot.children) walk(child, index);
            }
        };
        walk(root, null);
        dialogs.push(nodes);
    }
    return dialogs;
}
