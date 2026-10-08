import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const require = createRequire(import.meta.url);
const sources = Object.fromEntries([
  ['react', 'react', 'react.production.js'],
  ['react-dom', 'react-dom', 'react-dom.production.js'],
  ['react-dom/client', 'react-dom', 'react-dom-client.production.js'],
  ['scheduler', 'scheduler', 'scheduler.production.js'],
].map(([id, pkg, file]) => [id, readFileSync(join(dirname(require.resolve(pkg)), 'cjs', file), 'utf8')]));

process.stdout.write(`<html><head><title>Controlled temporal fixture</title></head><body><div id="root"></div><script>
(() => {
  const sources = ${JSON.stringify(sources).replaceAll('</script', '<\\/script')}, loaded = {};
  function require(id) {
    if (!loaded[id]) {
      const module = loaded[id] = { exports: {} };
      new Function('module', 'exports', 'require', sources[id])(module, module.exports, require);
    }
    return loaded[id].exports;
  }
  const React = require('react'), { createRoot } = require('react-dom/client');
  function App() {
    const [value, setValue] = React.useState({date: '2026-10-02', datetime: '2026-10-02T23:00', start: '2026-10-02T10:00', end: '2026-10-02T11:00', title: 'Fixture', timezone: 'UTC'});
    const [revision, setRevision] = React.useState(0);
    const [reject, setReject] = React.useState(false);
    function change(key, initial) {
      return e => {
        setValue({...value, [key]: e.target.value});
        if (reject) setTimeout(() => setValue(v => ({...v, [key]: initial})), 0);
      };
    }
    return React.createElement('section', null,
      React.createElement('label', {htmlFor: 'date'}, 'Start'),
      React.createElement('input', {id: 'date', type: 'date', role: 'textbox', placeholder: 'Start', title: 'Start', 'data-testid': 'date', value: value.date, onChange: change('date', '2026-10-02')}),
      React.createElement('label', {htmlFor: 'datetime'}, 'End'),
      React.createElement('input', {id: 'datetime', type: 'datetime-local', role: 'textbox', placeholder: 'End', title: 'End', 'data-testid': 'datetime', value: value.datetime, onChange: change('datetime', '2026-10-02T23:00')}),
      ...[['title', 'Title', 'text'], ['start', 'Event start', 'datetime-local'], ['end', 'Event end', 'datetime-local'], ['timezone', 'Event time zone', 'text']].map(([key, label, type]) => React.createElement('label', {key}, label, React.createElement('input', {id: key, type, value: value[key], onChange: e => setValue({...value, [key]: e.target.value})}))),
      React.createElement('output', {id: 'state'}, JSON.stringify({...value, revision})),
      React.createElement('button', {id: 'save', onClick: () => document.getElementById('saved').textContent = JSON.stringify(value)}, 'Save'),
      React.createElement('output', {id: 'saved'}),
      React.createElement('button', {id: 'rerender', onClick: () => setRevision(v => v + 1)}, 'Rerender'),
      React.createElement('button', {id: 'reject', onClick: () => setReject(true)}, 'Reject after change'));
  }
  createRoot(document.getElementById('root')).render(React.createElement(App));
})();</script></body></html>`);
