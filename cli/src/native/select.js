async function(vals) {
            if (!this.isConnected) return { error: 'select_target_detached: Select is detached; no events dispatched' };
            if (this.tagName !== 'SELECT') return { error: 'select_not_editable: Target must be a native select, not a combobox wrapper; no events dispatched' };
            if (this.matches(':disabled') || this.closest('[inert]') || this.getAttribute('aria-disabled') === 'true') {
                return { error: 'select_not_editable: Select is disabled; no events dispatched' };
            }
            const view = this.ownerDocument.defaultView;
            const normalize = (value) => String(value ?? '')
                .replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '')
                .replace(/\s+/g, ' ')
                .trim();
            const options = Array.from(this.options);
            const wanted = new Set();
            for (const value of vals) {
                let matches = options.filter((opt) =>
                    value === opt.value ||
                    value === opt.label.trim() ||
                    value === opt.textContent.trim()
                );
                if (matches.length === 0) {
                    const normalizedValue = normalize(value);
                    matches = options.filter((opt) =>
                        normalize(opt.label) === normalizedValue
                    );
                    if (matches.length > 1) {
                        return { error: 'select_ambiguous_option: Multiple options matched ' + JSON.stringify(value) + ' after whitespace normalization' };
                    }
                }
                if (matches.length === 0) {
                    const available = options.map(o => o.value + ' ("' + normalize(o.label) + '")').join(', ');
                    return { error: 'select_option_not_found: No option matched ' + JSON.stringify(vals) + '. Available options: ' + available };
                }
                for (const opt of matches) wanted.add(opt);
            }
            if (wanted.size === 0) {
                const available = options.map(o => o.value + ' ("' + normalize(o.label) + '")').join(', ');
                return { error: 'select_option_not_found: No option matched ' + JSON.stringify(vals) + '. Available options: ' + available };
            }
            if (!this.multiple && wanted.size !== 1) {
                return { error: 'select_ambiguous_option: A single select requires exactly one matching option; no events dispatched' };
            }
            if ([...wanted].some(opt => opt.disabled || opt.parentElement?.matches('optgroup:disabled'))) {
                return { error: 'select_not_editable: Requested option is disabled; no events dispatched' };
            }
            // Assign a single select once, through its native setter, rather
            // than toggling every option in a controlled application.
            if (this.multiple) {
                const setter = Object.getOwnPropertyDescriptor(view.HTMLOptionElement.prototype, 'selected').set;
                for (const opt of options) setter.call(opt, wanted.has(opt));
            } else {
                const setter = Object.getOwnPropertyDescriptor(view.HTMLSelectElement.prototype, 'selectedIndex').set;
                setter.call(this, options.indexOf([...wanted][0]));
            }
            const expected = options.map(opt => wanted.has(opt));
            this.dispatchEvent(new view.Event('input', { bubbles: true }));
            this.dispatchEvent(new view.Event('change', { bubbles: true }));
            // React can restore its controlled value after an event or at the
            // next render. Observe that render, but never replay the selection.
            const rendered = await new Promise(resolve => {
                let first, second, task;
                const done = result => {
                    view.clearTimeout(deadline);
                    view.cancelAnimationFrame(first);
                    view.cancelAnimationFrame(second);
                    view.clearTimeout(task);
                    resolve(result);
                };
                const deadline = view.setTimeout(() => done(false), 100);
                first = view.requestAnimationFrame(() => {
                    second = view.requestAnimationFrame(() => {
                        task = view.setTimeout(() => done(true), 0);
                    });
                });
            });
            if (!rendered) return { error: 'select_render_timeout: Selection dispatched but rendering did not complete; retention is unknown; do not replay' };
            if (!this.isConnected) return { error: 'select_target_detached: Select was replaced after dispatch; inspect the current page before another action' };
            const actual = Array.from(this.options);
            if (actual.length !== options.length || actual.some((opt, index) => opt !== options[index] || opt.selected !== expected[index])) {
                return { error: 'select_value_not_retained: Select did not retain the requested options after rendering; inspect the current page before another action' };
            }
            return { matched: wanted.size };
        }
