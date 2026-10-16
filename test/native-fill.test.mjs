import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const fill = new Function(`return (${readFileSync(new URL('../cli/src/native/fill.js', import.meta.url), 'utf8')});`)();

function fixture() {
  let next = 0;
  const timers = new Map(), frames = new Map(), events = [];
  class Input {
    constructor() { this.tagName = 'INPUT'; this.type = 'date'; this.isConnected = true; this.stored = '2026-10-02'; this.reads = 0; }
    get value() { this.reads++; return this.stored; }
    set value(value) { this.stored = value; }
    matches() { return false; }
    focus() {}
    dispatchEvent(event) { events.push(event.type); }
  }
  const view = {
    HTMLInputElement: Input,
    Event: class { constructor(type) { this.type = type; } },
    setTimeout: (callback, delay) => { const id = ++next; timers.set(id, {callback, delay}); return id; },
    clearTimeout: id => timers.delete(id),
    requestAnimationFrame: callback => { const id = ++next; frames.set(id, callback); return id; },
    cancelAnimationFrame: id => frames.delete(id),
  };
  const input = new Input();
  input.ownerDocument = {defaultView: view, createElement: () => new Input()};
  const frame = () => {
    assert.equal(frames.size, 1);
    const [id, callback] = frames.entries().next().value;
    frames.delete(id); callback();
  };
  const timer = delay => {
    const entry = [...timers].find(([, item]) => item.delay === delay);
    assert.ok(entry, `timer ${delay} must exist`);
    timers.delete(entry[0]); entry[1].callback();
  };
  const clean = () => { assert.equal(frames.size, 0); assert.equal(timers.size, 0); };
  return {input, events, frames, timers, frame, timer, clean};
}

for (const completed of [0, 1, 2]) {
  test(`fill render barrier times out with ${completed} frames and no post-render task`, async () => {
    const f = fixture();
    const pending = fill.call(f.input, '2030-01-01');
    for (let i = 0; i < completed; i++) f.frame();
    assert.equal(f.input.reads, 0, 'retention cannot be read before the barrier');
    f.timer(100);
    assert.deepEqual(await pending, {status: 'render_timeout'});
    assert.equal(f.input.reads, 0, 'timeout cannot be promoted to retained-value success');
    assert.deepEqual(f.events, ['input', 'change'], 'exactly one effect dispatch');
    f.clean();
  });
}

test('fill render barrier requires both frames and the following task', async () => {
  const f = fixture();
  let settled = false;
  const pending = fill.call(f.input, '2030-01-01').then(value => { settled = true; return value; });
  f.frame(); f.frame();
  await Promise.resolve();
  assert.equal(settled, false);
  f.timer(0);
  assert.deepEqual(await pending, {status: 'filled'});
  f.clean();
});

test('fill render barrier observes rejection committed after the first frame', async () => {
  const f = fixture();
  const pending = fill.call(f.input, '2030-01-01');
  f.frame(); f.input.value = '2026-10-02'; f.frame(); f.timer(0);
  assert.deepEqual(await pending, {status: 'value_not_retained'});
  f.clean();
});

test('fill render barrier checks target attachment after completion', async () => {
  const f = fixture();
  const pending = fill.call(f.input, '');
  f.frame(); f.input.isConnected = false; f.frame(); f.timer(0);
  assert.deepEqual(await pending, {status: 'target_detached'});
  assert.deepEqual(f.events, ['input', 'change']);
  f.clean();
});
