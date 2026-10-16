function() {
    'use strict';
    const doc = document;
    const view = doc.defaultView;
    const root = doc.documentElement;
    const href = view.location.href;
    const own = 'kenan@liminal.co';
    const origin = 'https://accounts.google.com';
    let pinned = null;
    let setterUsed = false;
    let filled = false;
    let clickUsed = false;
    let terminal = null;
    let observer = null;
    let expiry = null;
    const result = state => ({state});
    function cleanup() {
        if (observer) observer.disconnect();
        if (expiry !== null) { view.clearTimeout(expiry); expiry = null; }
    }
    const fail = () => {
        terminal = setterUsed || clickUsed ? 'unknown' : 'refused';
        cleanup();
        return result(terminal);
    };
    function trusted(url) {
        return url.origin === origin && !url.username && !url.password;
    }
    function sameDocument() {
        return document === doc && doc.defaultView === view && view.document === doc &&
            view === view.top && doc.documentElement === root && root.isConnected &&
            view.location.href === href && trusted(new URL(view.location.href));
    }
    function visible(el) {
        if (!el.isConnected || el.ownerDocument !== doc || !el.getClientRects().length ||
            el.closest('[hidden],[inert],[aria-hidden="true"]')) return false;
        for (let node = el; node; node = node.parentElement) {
            const style = view.getComputedStyle(node);
            if (style.visibility !== 'visible' || style.display === 'none' || Number(style.opacity) === 0) return false;
        }
        return true;
    }
    const usable = el => visible(el) && !el.matches(':disabled') && el.getAttribute('aria-disabled') !== 'true';
    const editable = el => usable(el) && !el.readOnly;
    const query = selector => Array.from(doc.querySelectorAll(selector));
    function account(required) {
        const values = [
            ...query('[data-identifier]').map(el => el.getAttribute('data-identifier')),
            ...query('input[name="identifier"],input[type="email"]').map(el => el.value),
        ].filter(value => typeof value === 'string' && value.length > 0);
        return (!required || values.length > 0) && values.every(value => value === own);
    }
    function formBinding(control, button) {
        const form = control.form;
        if (!form || form.ownerDocument !== doc || !form.isConnected ||
            form.method.toUpperCase() !== 'POST' || (button && button.form !== form)) return null;
        const action = new URL(form.action, doc.baseURI);
        if (!trusted(action)) return null;
        if (button && (button.hasAttribute('formaction') || button.hasAttribute('formmethod') ||
            button.hasAttribute('formtarget') || button.type !== 'button' && button.type !== 'submit')) return null;
        if (form.target && form.target !== '_self') return null;
        return {form, action: action.href};
    }
    function classify() {
        if (!sameDocument() || !account(false)) return {state: 'refused'};
        const allEmails = query('input[type="email"]');
        const allPasswords = query('input[type="password"]');
        const emails = allEmails.filter(editable);
        const passwords = allPasswords.filter(editable);
        if (allPasswords.length && !passwords.length) return {state: 'refused'};
        const challenge = query('[data-challengetype],input[name="totpPin"],input[name="idvPin"],input[name="backupCodePin"],#totpPin,#idvPin,#backupCodePin').filter(visible);
        if (passwords.length) {
            if (passwords.length !== 1 || emails.length || challenge.length || !account(true)) return {state: 'refused'};
            const control = passwords[0];
            if (control.name !== 'Passwd') return {state: 'refused'};
            const buttons = query('#passwordNext button').filter(usable);
            if (buttons.length !== 1) return {state: 'refused'};
            const binding = formBinding(control, buttons[0]);
            if (!binding) return {state: 'refused'};
            // Match the password handler's identity evidence, not an arbitrary email input.
            const accounts = [...query('[data-identifier]').map(el => el.getAttribute('data-identifier')),
                ...Array.from(binding.form.querySelectorAll('input[type="hidden"][name="identifier"]')).map(el => el.value)]
                .filter(value => typeof value === 'string' && value.length > 0);
            if (!accounts.length || accounts.some(value => value !== own)) return {state: 'refused'};
            return {state: 'password-ready', control, button: buttons[0], ...binding};
        }
        if (challenge.length) {
            if (emails.length || !account(true) || !/^\/v\d+\/signin\/challenge\//.test(view.location.pathname) &&
                !/^\/signin\/v\d+\/challenge\//.test(view.location.pathname)) return {state: 'refused'};
            const controls = query('input').filter(el => editable(el) && el.type !== 'hidden');
            const forms = query('form').filter(el => el.isConnected);
            if (forms.length !== 1 || controls.some(el => el.form !== forms[0])) return {state: 'refused'};
            const binding = formBinding({form: forms[0]}, null);
            if (!binding || !challenge.every(el => forms[0].contains(el))) return {state: 'refused'};
            return {state: 'challenge-ready', ...binding};
        }
        if (emails.length !== 1) return {state: allEmails.length ? 'refused' : 'unknown'};
        const control = emails[0];
        if (control.value !== '' && control.value !== own) return {state: 'refused'};
        const buttons = query('#identifierNext button').filter(usable);
        if (buttons.length !== 1) return {state: 'refused'};
        const binding = formBinding(control, buttons[0]);
        if (!binding) return {state: 'refused'};
        return {state: 'identifier-ready', control, button: buttons[0], ...binding};
    }
    function changed(records) {
        if (!pinned) return false;
        return records.some(record => {
            if (record.type === 'attributes') return (
                record.target === pinned.form && ['action','method','target','id'].includes(record.attributeName) ||
                record.target === pinned.control && ['type','name','form','id','disabled','readonly'].includes(record.attributeName) ||
                record.target === pinned.button && ['type','form','formaction','formmethod','formtarget','disabled'].includes(record.attributeName) ||
                record.attributeName === 'data-identifier' ||
                pinned.accounts.includes(record.target) && ['value','name','type'].includes(record.attributeName));
            return Array.from(record.removedNodes).some(node =>
                [pinned.form, pinned.control, pinned.button, root, ...pinned.accounts].some(bound => bound && (node === bound || node.contains(bound))));
        });
    }
    function current() {
        if (terminal) return null;
        if (observer && changed(observer.takeRecords())) { fail(); return null; }
        const next = classify();
        const accounts = query('[data-identifier],input[name="identifier"],input[type="email"]');
        if (!pinned || next.state !== pinned.state || next.form !== pinned.form ||
            next.control !== pinned.control || next.button !== pinned.button || next.action !== pinned.action ||
            accounts.length !== pinned.accounts.length || accounts.some((el, i) => el !== pinned.accounts[i])) {
            fail(); return null;
        }
        return next;
    }
    function inspect() {
        try {
            if (terminal) return result(terminal);
            if (pinned) return current() ? result(pinned.state) : result(terminal);
            const next = classify();
            if (!['identifier-ready','password-ready','challenge-ready'].includes(next.state)) {
                terminal = next.state;
                cleanup();
                return result(terminal);
            }
            pinned = {...next, accounts: query('[data-identifier],input[name="identifier"],input[type="email"]')};
            if (next.state === 'identifier-ready') {
                observer = new view.MutationObserver(records => { if (changed(records)) fail(); });
                observer.observe(root, {subtree: true, childList: true, attributes: true});
                expiry = view.setTimeout(() => { fail(); }, 35000);
            } else {
                cleanup();
            }
            return result(next.state);
        } catch { return fail(); }
    }
    async function fillIdentifier() {
        try {
            if (terminal) return result(terminal);
            if (setterUsed || clickUsed) return result('unknown');
            if (!pinned || pinned.state !== 'identifier-ready' || !current()) return fail();
            const setter = Object.getOwnPropertyDescriptor(view.HTMLInputElement.prototype, 'value').set;
            setterUsed = true;
            setter.call(pinned.control, own);
            if (!current() || pinned.control.value !== own) return fail();
            pinned.control.dispatchEvent(new view.Event('input', {bubbles: true}));
            if (!current() || pinned.control.value !== own) return fail();
            pinned.control.dispatchEvent(new view.Event('change', {bubbles: true}));
            if (!current() || pinned.control.value !== own) return fail();
            await new Promise(resolve => view.setTimeout(resolve, 100));
            if (!current() || pinned.control.value !== own) return fail();
            filled = true;
            return result('identifier-filled');
        } catch { return fail(); }
    }
    function clickNext() {
        try {
            if (terminal) return result(terminal);
            if (clickUsed) return result('unknown');
            if (!filled || !current() || pinned.control.value !== own) return fail();
            clickUsed = true;
            // Mark before dispatch: throws and missing acknowledgements cannot permit replay.
            cleanup();
            pinned.button.click();
            return result('next-dispatched');
        } catch { return fail(); }
    }
    return Object.freeze({
        inspect,
        fillIdentifier,
        clickNext,
        identifierNode() {
            try { return !clickUsed && pinned && pinned.state === 'identifier-ready' && current() ? pinned.control : null; }
            catch { fail(); return null; }
        },
        dispose() { return fail(); },
        readiness() {
            const observation = inspect();
            cleanup();
            if (observation.state === 'identifier-ready') {
                terminal = 'unknown';
                return result('unknown');
            }
            return observation;
        },
    });
}
