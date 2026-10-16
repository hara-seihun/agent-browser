import assert from 'node:assert/strict';
import test from 'node:test';
import {fixture, identifierHTML, passwordHTML, challengeHTML, identity, factorySource} from './work-readiness-fixture.mjs';

const state = value => JSON.parse(JSON.stringify(value));
const pageReasons = new Set(['document-binding','account-mismatch','password-control-unavailable','ambiguous-password-controls','mixed-login-controls','account-evidence-missing','password-control-identity','password-next-unavailable','form-binding','form-action','submit-override','form-target','challenge-route','challenge-form','identifier-control-unavailable','identifier-control-ambiguous','identifier-next-unavailable','pinned-mutation','binding-changed','identifier-value-changed','transition-order','already-dispatched','policy-exception','policy-expired','policy-disposed','readiness-not-reached']);
const is = (value, expected) => {
    const observed = state(value);
    assert.equal(observed.state, expected);
    if (expected === 'refused' || expected === 'unknown') {
        assert.deepEqual(Object.keys(observed).sort(), ['reason', 'state']);
        assert.ok(pageReasons.has(observed.reason), JSON.stringify(observed));
    } else assert.deepEqual(observed, {state: expected});
};
const why = (value, expectedState, reason) => assert.deepEqual(state(value), {state: expectedState, reason});
function check(name, options, run) {
    test(name, async () => { const f = fixture(options); try { await run(f); } finally { f.close(); } });
}
check('one setter, input/change, one Next and no provider, with private node identity', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready');
    assert.equal(f.policy.identifierNode(), f.document.querySelector('input'));
    is(await f.policy.fillIdentifier(), 'identifier-filled');
    assert.equal(f.document.querySelector('input').value, identity);
    is(f.policy.clickNext(), 'next-dispatched');
    is(f.policy.clickNext(), 'unknown');
    is(await f.policy.fillIdentifier(), 'unknown');
    assert.deepEqual(f.counters, {setters: 1, inputs: 1, changes: 1, clicks: 1, provider: 0});
});
check('already-own identifier still permits exactly one setter', {}, async f => {
    f.document.querySelector('input').value = identity;
    f.counters.setters = 0;
    is(f.policy.inspect(), 'identifier-ready');
    is(await f.policy.fillIdentifier(), 'identifier-filled');
    is(f.policy.clickNext(), 'next-dispatched');
    assert.equal(f.counters.setters, 1);
});
for (const [name, mutate] of [
    ['foreign identifier', f => f.document.querySelector('input').value = 'someone@example.test'],
    ['contradictory marker', f => f.document.body.insertAdjacentHTML('beforeend', '<span data-identifier="someone@example.test"></span>')],
    ['contradictory hidden', f => f.document.body.insertAdjacentHTML('beforeend', '<input type="hidden" name="identifier" value="someone@example.test">')],
    ['two usable email controls', f => f.document.querySelector('form').insertAdjacentHTML('afterbegin', '<input type="email">')],
    ['readonly control', f => f.document.querySelector('input').readOnly = true],
    ['disabled fieldset', f => f.document.querySelector('input').outerHTML = '<fieldset disabled><input type="email"></fieldset>'],
    ['hidden control', f => f.document.querySelector('input').style.visibility = 'hidden'],
    ['inert parent', f => f.document.querySelector('form').setAttribute('inert', '')],
    ['missing Next', f => f.document.querySelector('button').remove()],
    ['duplicate Next', f => f.document.querySelector('#identifierNext').insertAdjacentHTML('beforeend', '<button type="button">Next</button>')],
    ['disabled Next', f => f.document.querySelector('button').disabled = true],
    ['aria-disabled Next', f => f.document.querySelector('button').setAttribute('aria-disabled', 'true')],
    ['foreign action', f => f.document.querySelector('form').action = 'https://foreign.test/submit'],
    ['credentialed action', f => f.document.querySelector('form').action = 'https://user@accounts.google.com/submit'],
    ['GET form', f => f.document.querySelector('form').method = 'get'],
    ['foreign form target', f => f.document.querySelector('form').target = '_blank'],
    ['button form override', f => f.document.querySelector('button').setAttribute('formaction', '/other')],
    ['button foreign form', f => { f.document.body.insertAdjacentHTML('beforeend', '<form id="other" method="post"></form>'); f.document.querySelector('button').setAttribute('form', 'other'); }],
]) check(`initial refusal: ${name}`, {}, async f => {
    mutate(f); f.counters.setters = 0;
    is(f.policy.inspect(), 'refused');
    assert.equal(f.policy.identifierNode(), null);
    is(await f.policy.fillIdentifier(), 'refused');
    assert.equal(f.counters.setters, 0); assert.equal(f.counters.clicks, 0);
});
for (const url of ['http://accounts.google.com/v3/signin/identifier', 'https://accounts.google.com.evil.test/', 'https://user@accounts.google.com/', 'https://accounts.google.com:444/'])
    check(`origin refusal ${url}`, {url}, f => { is(f.policy.inspect(), 'refused'); assert.equal(f.counters.setters, 0); });
for (const [name, mutate] of [
    ['same-document email replacement', f => f.document.querySelector('input').outerHTML = '<input type="email" name="identifier">'],
    ['same-document form replacement', f => f.document.querySelector('form').outerHTML = identifierHTML],
    ['same-document button replacement', f => f.document.querySelector('button').outerHTML = '<button type="button">Next</button>'],
    ['action changed', f => f.document.querySelector('form').action = '/other'],
    ['action changed then restored', f => { const form = f.document.querySelector('form'); const action = form.action; form.action = '/other'; form.action = action; }],
    ['email removed and reinserted', f => { const input = f.document.querySelector('input'); input.remove(); f.document.querySelector('form').prepend(input); }],
    ['document root replaced', f => f.document.documentElement.replaceWith(f.document.documentElement.cloneNode(true))],
    ['same-document URL changed', f => f.window.history.replaceState({}, '', '/other')],
]) {
    check(`before setter ${name}`, {}, async f => {
        is(f.policy.inspect(), 'identifier-ready'); mutate(f);
        assert.equal(f.policy.identifierNode(), null);
        is(await f.policy.fillIdentifier(), 'refused');
        assert.equal(f.counters.setters, 0); assert.equal(f.counters.clicks, 0);
    });
    check(`before click ${name}`, {}, async f => {
        is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled'); mutate(f);
        is(f.policy.clickNext(), 'unknown'); assert.equal(f.counters.clicks, 0);
    });
}
for (const event of ['input', 'change']) check(`event ${event} action swap interrupts remaining dispatch`, {}, async f => {
    f.document.querySelector('input').addEventListener(event, () => f.document.querySelector('form').action = '/changed');
    is(f.policy.inspect(), 'identifier-ready');
    is(await f.policy.fillIdentifier(), 'unknown'); is(f.policy.clickNext(), 'unknown');
    assert.equal(f.counters.setters, 1); assert.equal(f.counters.clicks, 0);
    assert.equal(f.counters.changes, event === 'input' ? 0 : 1);
});
check('retention reset on a later task yields unknown and never clicks', {}, async f => {
    f.document.querySelector('input').addEventListener('change', () => f.window.setTimeout(() => { f.document.querySelector('input').value = ''; }, 0));
    is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'unknown');
    is(f.policy.clickNext(), 'unknown'); assert.equal(f.counters.clicks, 0);
});
check('concurrent second fill never issues a second setter', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); const pending = f.policy.fillIdentifier();
    is(await f.policy.fillIdentifier(), 'unknown'); is(await pending, 'identifier-filled');
    assert.equal(f.counters.setters, 1);
});
check('click exception is unknown and never retried', {}, async f => {
    const button = f.document.querySelector('button'); let attempts = 0;
    button.click = () => { attempts++; throw new Error('private diagnostic'); };
    is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled');
    is(f.policy.clickNext(), 'unknown'); is(f.policy.clickNext(), 'unknown'); assert.equal(attempts, 1);
});
check('Next before setter refuses without effect', {}, f => { is(f.policy.inspect(), 'identifier-ready'); is(f.policy.clickNext(), 'refused'); assert.equal(f.counters.clicks, 0); });
check('existing password is strictly own, metadata-only and has no mutations', {html: passwordHTML, url: 'https://accounts.google.com/v3/signin/challenge/pwd'}, f => {
    is(f.policy.inspect(), 'password-ready'); is(f.policy.readiness(), 'password-ready');
    assert.equal(f.policy.identifierNode(), null); assert.equal(f.counters.setters, 0); assert.equal(f.counters.clicks, 0);
});
for (const [name, mutate] of [
    ['no identity', f => { f.document.querySelector('[data-identifier]').remove(); f.document.querySelector('input[type="hidden"]').remove(); }],
    ['foreign identity', f => f.document.querySelector('[data-identifier]').setAttribute('data-identifier', 'someone@example.test')],
    ['two passwords', f => f.document.querySelector('form').insertAdjacentHTML('beforeend', '<input type="password" name="Passwd">')],
    ['wrong password name', f => f.document.querySelector('input[type="password"]').name = 'Other'],
    ['disabled password', f => f.document.querySelector('input[type="password"]').disabled = true],
    ['Next on different form', f => { f.document.querySelector('form').id = 'pwd'; f.document.body.insertAdjacentHTML('beforeend', '<form id="other" method="post"></form>'); f.document.querySelector('button').setAttribute('form', 'other'); }],
]) check(`password refusal ${name}`, {html: passwordHTML}, f => { mutate(f); is(f.policy.readiness(), 'refused'); assert.equal(f.counters.clicks, 0); });
check('existing challenge, own POST identity, never handles or submits challenge', {html: challengeHTML, url: 'https://accounts.google.com/v3/signin/challenge/totp'}, async f => {
    is(f.policy.readiness(), 'challenge-ready'); is(await f.policy.fillIdentifier(), 'refused'); assert.equal(f.counters.setters, 0); assert.equal(f.counters.clicks, 0);
});
for (const [name, html, url] of [
    ['missing own identity', challengeHTML.replaceAll(identity, ''), 'https://accounts.google.com/v3/signin/challenge/totp'],
    ['foreign own identity', challengeHTML.replaceAll(identity, 'someone@example.test'), 'https://accounts.google.com/v3/signin/challenge/totp'],
    ['GET form', challengeHTML.replace('method="post"', 'method="get"'), 'https://accounts.google.com/v3/signin/challenge/totp'],
    ['nonchallenge path', challengeHTML, 'https://accounts.google.com/v3/signin/identifier'],
]) check(`challenge refusal ${name}`, {html, url}, f => is(f.policy.readiness(), 'refused'));
check('unsupported page returns closed unknown', {html: '<main>PRIVATE BODY https://secret.test?q=private</main>'}, f => {
    is(f.policy.readiness(), 'unknown'); assert.equal(JSON.stringify(f.policy.inspect()).includes('PRIVATE'), false);
});
for (const [name, html, path, expected] of [['password', passwordHTML, 'pwd', 'password-ready'], ['challenge', challengeHTML, 'totp', 'challenge-ready']])
    check(`intended transition to ${name} requires fresh factory binding`, {}, async f => {
        is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled');
        f.document.querySelector('button').addEventListener('click', () => {
            f.document.body.innerHTML = html;
            f.window.history.replaceState({}, '', `/v3/signin/challenge/${path}`);
        });
        is(f.policy.clickNext(), 'next-dispatched'); is(f.fresh().readiness(), expected);
        is(f.policy.readiness(), 'unknown'); assert.equal(f.counters.clicks, 1);
    });
for (const [name, mutate] of [
    ['marker changed then restored', f => { const marker = f.document.querySelector('[data-identifier]'); marker.setAttribute('data-identifier', 'foreign@example.test'); marker.setAttribute('data-identifier', identity); }],
    ['marker replacement', f => { const marker = f.document.querySelector('[data-identifier]'); marker.replaceWith(marker.cloneNode(true)); }],
    ['hidden identity replacement', f => { const hidden = f.document.querySelector('input[type="hidden"]'); hidden.replaceWith(hidden.cloneNode(true)); }],
    ['own identity inserted after pin', f => f.document.body.insertAdjacentHTML('beforeend', `<span data-identifier="${identity}"></span>`)],
]) check(`account binding ${name}`, {html: identifierHTML.replace('<input id=', `<span data-identifier="${identity}"></span><input type="hidden" name="identifier" value="${identity}"><input id=`)}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); mutate(f);
    assert.equal(f.policy.identifierNode(), null); is(await f.policy.fillIdentifier(), 'refused');
    assert.equal(f.counters.setters, 0); assert.equal(f.counters.clicks, 0);
});
check('same-document newly foreign marker refuses after own retained setter', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled');
    f.document.body.insertAdjacentHTML('beforeend', '<span data-identifier="foreign@example.test"></span>');
    is(f.policy.clickNext(), 'unknown'); assert.equal(f.counters.clicks, 0);
});
check('invisible parent opacity cannot admit an invisible email or Next', {}, async f => {
    f.document.querySelector('form').style.opacity = '0';
    is(f.policy.inspect(), 'refused'); is(await f.policy.fillIdentifier(), 'refused');
    assert.equal(f.counters.setters, 0);
});
check('adopted foreign-document email refuses', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready');
    const other = f.document.implementation.createHTMLDocument('other');
    other.body.append(other.adoptNode(f.document.querySelector('input')));
    assert.equal(f.policy.identifierNode(), null); is(await f.policy.fillIdentifier(), 'refused');
    assert.equal(f.counters.setters, 0);
});
check('child frame factory refuses', {}, f => {
    const iframe = f.document.createElement('iframe'); f.document.body.append(iframe);
    iframe.contentDocument.body.innerHTML = identifierHTML;
    const child = iframe.contentWindow.eval(`(${factorySource})()`);
    is(child.inspect(), 'refused');
    assert.equal(child.identifierNode(), null);
});
function clean(f) { assert.equal(f.resources.observers.size, 0); assert.equal(f.resources.timers.size, 0); }
check('identifier permit expires before mutation and invalidates/disconnects', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready');
    assert.equal(f.resources.observers.size, 1);
    assert.equal([...f.resources.timers.values()].filter(timer => timer.delay === 35000).length, 1);
    f.expire(); clean(f);
    is(await f.policy.fillIdentifier(), 'refused'); assert.equal(f.policy.identifierNode(), null);
    assert.equal(f.counters.setters, 0);
});
check('identifier permit expiry after setter preserves uncertainty and forbids Next', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled');
    f.expire(); clean(f); is(f.policy.clickNext(), 'unknown'); assert.equal(f.counters.clicks, 0);
});
check('native cancellation dispose revokes the filled permit and cleans resources', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled');
    is(f.policy.dispose(), 'unknown'); clean(f);
    is(f.policy.clickNext(), 'unknown'); assert.equal(f.policy.identifierNode(), null);
});
check('dispose during retention produces no late click and cleans observer', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); const pending = f.policy.fillIdentifier();
    is(f.policy.dispose(), 'unknown');
    is(await pending, 'unknown'); clean(f); is(f.policy.clickNext(), 'unknown');
    assert.equal(f.counters.clicks, 0);
});
check('click disconnects observer and deadline before invoking page handler', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready'); is(await f.policy.fillIdentifier(), 'identifier-filled');
    f.document.querySelector('button').addEventListener('click', () => clean(f));
    is(f.policy.clickNext(), 'next-dispatched'); clean(f);
});
for (const [label, html, url] of [
    ['password', passwordHTML, 'https://accounts.google.com/v3/signin/challenge/pwd'],
    ['challenge', challengeHTML, 'https://accounts.google.com/v3/signin/challenge/totp'],
    ['unknown', '<main>unsupported</main>', 'https://accounts.google.com/'],
    ['identifier', identifierHTML, 'https://accounts.google.com/v3/signin/identifier'],
    ['refused', identifierHTML, 'https://foreign.test/'],
]) check(`readiness ${label} releases all observers and deadlines`, {html, url}, f => {
    f.policy.readiness(); clean(f);
    for (let i = 0; i < 10; i++) f.fresh().readiness();
    clean(f);
});
for (const [name, html, reason] of [
    ['foreign action', identifierHTML.replace('action="/v3/signin/identifier"', 'action="https://private.invalid/?secret=sentinel"'), 'form-action'],
    ['GET form', identifierHTML.replace('method="post"', 'method="get"'), 'form-binding'],
    ['form target', identifierHTML.replace('<form ', '<form target="_blank" '), 'form-target'],
    ['button override', identifierHTML.replace('<button ', '<button formaction="/private" '), 'submit-override'],
    ['missing email', '<main>PRIVATE TEXT</main>', 'identifier-control-unavailable'],
    ['duplicate email', identifierHTML.replace('<input id=', '<input type="email"><input id='), 'identifier-control-ambiguous'],
    ['missing identifier Next', identifierHTML.replace('id="identifierNext"', ''), 'identifier-next-unavailable'],
    ['missing account', passwordHTML.replaceAll(identity, ''), 'account-evidence-missing'],
    ['foreign account', passwordHTML.replaceAll(identity, 'private@example.invalid'), 'account-mismatch'],
    ['wrong password name', passwordHTML.replace('name="Passwd"', 'name="private"'), 'password-control-identity'],
    ['missing password Next', passwordHTML.replace('id="passwordNext"', ''), 'password-next-unavailable'],
    ['disabled password', passwordHTML.replace('type="password"', 'type="password" disabled'), 'password-control-unavailable'],
    ['duplicate password', passwordHTML.replace('<input type="password"', '<input type="password" name="Passwd"><input type="password"'), 'ambiguous-password-controls'],
    ['mixed controls', passwordHTML.replace('<input type="password"', '<input type="email"><input type="password"'), 'mixed-login-controls'],
]) check('causal closed discriminator: '+name, {html}, f => {
    const expected = reason === 'identifier-control-unavailable' ? 'unknown' : 'refused';
    why(f.policy.inspect(), expected, reason);why(f.policy.dispose(), expected, reason);
    assert.equal(f.counters.setters, 0);assert.equal(f.counters.clicks, 0);clean(f);
});
check('latched event mutation survives later disposal without losing cause or allowing click', {}, async f => {
    is(f.policy.inspect(), 'identifier-ready');
    f.document.querySelector('input').addEventListener('input', () => {
        const form=f.document.querySelector('form');const action=form.action;form.action='/private';form.action=action;
    });
    why(await f.policy.fillIdentifier(), 'unknown', 'pinned-mutation');
    why(f.policy.dispose(), 'unknown', 'pinned-mutation');why(f.policy.clickNext(), 'unknown', 'pinned-mutation');
    assert.deepEqual(f.counters, {setters:1,inputs:1,changes:0,clicks:0,provider:0});clean(f);
});
check('property-only identifier value loss has its own closed cause', {}, async f => {
    is(f.policy.inspect(),'identifier-ready');
    f.document.querySelector('input').addEventListener('input', event => { event.target.value=''; });
    why(await f.policy.fillIdentifier(),'unknown','identifier-value-changed');assert.equal(f.counters.clicks,0);clean(f);
});
check('deadline reason survives a repeated Next and disposal', {}, f => {
    is(f.policy.inspect(),'identifier-ready');f.expire();
    why(f.policy.clickNext(),'refused','policy-expired');why(f.policy.dispose(),'refused','policy-expired');clean(f);
});
