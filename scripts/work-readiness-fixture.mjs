import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
// The caller names its installed DOM implementation; no browser or network is used.
const {JSDOM} = require(process.env.WORK_READINESS_JSDOM || 'jsdom');
export const factorySource = readFileSync(new URL('../cli/src/native/work_readiness.js', import.meta.url), 'utf8');
export const identity = 'kenan@liminal.co';
export const identifierHTML = `<form method="post" action="/v3/signin/identifier"><input id="identifierId" type="email" name="identifier"><div id="identifierNext"><button type="button">Next</button></div></form>`;
export const passwordHTML = `<form method="post" action="/v3/signin/challenge/pwd"><span data-identifier="${identity}"></span><input type="hidden" name="identifier" value="${identity}"><input type="password" name="Passwd"><div id="passwordNext"><button type="button">Next</button></div></form>`;
export const challengeHTML = `<form method="post" action="/v3/signin/challenge/totp"><span data-identifier="${identity}"></span><input type="hidden" name="identifier" value="${identity}"><input id="totpPin" name="totpPin" inputmode="numeric"><button type="button">Next</button></form>`;

export function fixture({html = identifierHTML, url = 'https://accounts.google.com/v3/signin/identifier'} = {}) {
    const dom = new JSDOM(`<!doctype html><html><body>${html}</body></html>`, {url, runScripts: 'outside-only', pretendToBeVisual: true});
    const {window} = dom;
    const {document} = window;
    // jsdom implements DOM/event/form behavior but has no layout engine.
    window.Element.prototype.getClientRects = function() {
        return this.isConnected && !this.closest('[hidden]') && window.getComputedStyle(this).display !== 'none' ? [{width: 100, height: 20}] : [];
    };
    const resources = {observers: new Set(), timers: new Map()};
    const Observer = window.MutationObserver;
    window.MutationObserver = class extends Observer {
        observe(...args) { resources.observers.add(this); return super.observe(...args); }
        disconnect() { resources.observers.delete(this); return super.disconnect(); }
    };
    const setTimer = window.setTimeout.bind(window);
    const clearTimer = window.clearTimeout.bind(window);
    window.setTimeout = (callback, delay) => {
        const id = setTimer(() => { resources.timers.delete(id); callback(); }, delay);
        resources.timers.set(id, {callback, delay});
        return id;
    };
    window.clearTimeout = id => { resources.timers.delete(id); clearTimer(id); };
    const expire = () => {
        const pending = [...resources.timers].find(([, timer]) => timer.delay === 35000);
        if (!pending) throw new Error('No live identifier permit deadline');
        const [id, timer] = pending;
        window.clearTimeout(id);
        timer.callback();
    };
    const expirePending = () => {
        const pending = [...resources.timers].find(([, timer]) => timer.delay === 2000);
        if (!pending) throw new Error('No live password observation deadline');
        const [id, timer] = pending;
        window.clearTimeout(id);
        timer.callback();
    };
    const counters = {setters: 0, inputs: 0, changes: 0, clicks: 0, provider: 0};
    const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
    Object.defineProperty(window.HTMLInputElement.prototype, 'value', {...descriptor, set(value) {
        counters.setters++;
        descriptor.set.call(this, value);
    }});
    document.addEventListener('input', () => counters.inputs++);
    document.addEventListener('change', () => counters.changes++);
    document.addEventListener('click', event => { counters.clicks++; event.preventDefault(); });
    const policy = window.eval(`(${factorySource})()`);
    return {dom, window, document, policy, counters, resources, expire, expirePending, fresh: () => window.eval(`(${factorySource})()`), close: () => window.close()};
}
