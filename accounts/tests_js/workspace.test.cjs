const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../static/js/workspace.js'), 'utf8');

function setup(isMobile = true, hasSidebar = true) {
  const events = {};
  const inside = {};
  let focusCalls = 0;
  const sidebar = { hidden: false, contains: element => element === inside };
  const toggle = {
    hidden: true, attrs: {},
    setAttribute(name, value) { this.attrs[name] = value; },
    addEventListener(name, handler) { events[name] = handler; },
    focus() { focusCalls++; document.activeElement = toggle; },
  };
  const media = {
    matches: isMobile,
    addEventListener(name, handler) { events[name] = handler; },
  };
  const document = {
    activeElement: null,
    getElementById(id) { return id === 'workspace-navigation' ? (hasSidebar ? sidebar : null) : toggle; },
    addEventListener(name, handler) { events[name] = handler; },
  };
  vm.runInNewContext(source, { document, window: { matchMedia: () => media } });
  return { events, sidebar, toggle, media, document, inside, focusCalls: () => focusCalls };
}

function assertVisible(state, visible) {
  assert.equal(state.sidebar.hidden, !visible);
  assert.equal(state.toggle.attrs['aria-expanded'], String(visible));
}

test('mobile toggle opens and closes with matching aria-expanded', () => {
  const state = setup();
  assertVisible(state, false);
  assert.equal(state.toggle.hidden, false);
  state.events.click();
  assertVisible(state, true);
  state.events.click();
  assertVisible(state, false);
});

for (const focus of ['inside', 'toggle']) {
  test(`Escape closes open mobile navigation with focus on ${focus}`, () => {
    const state = setup();
    state.events.click();
    state.document.activeElement = state[focus];
    state.events.keydown({ key: 'Escape' });
    assertVisible(state, false);
    assert.equal(state.document.activeElement, state.toggle);
    assert.ok(state.focusCalls() >= 1);
  });
}

test('Escape on closed mobile navigation does not move focus', () => {
  const state = setup();
  const elsewhere = {};
  state.document.activeElement = elsewhere;
  state.events.keydown({ key: 'Escape' });
  assertVisible(state, false);
  assert.equal(state.document.activeElement, elsewhere);
  assert.equal(state.focusCalls(), 0);
});

test('Escape leaves desktop sidebar and focus unchanged', () => {
  const state = setup(false);
  state.document.activeElement = state.inside;
  state.events.keydown({ key: 'Escape' });
  assertVisible(state, true);
  assert.equal(state.toggle.hidden, true);
  assert.equal(state.document.activeElement, state.inside);
  assert.equal(state.focusCalls(), 0);
});

test('resize synchronization remains intact and unrelated keys do nothing', () => {
  const state = setup();
  state.events.click();
  state.events.keydown({ key: 'Enter' });
  assertVisible(state, true);
  state.media.matches = false;
  state.events.change();
  assertVisible(state, true);
  assert.equal(state.toggle.hidden, true);
  state.media.matches = true;
  state.events.change();
  assertVisible(state, false);
  assert.equal(state.toggle.hidden, false);
});

test('specialized layouts without sidebar install no listeners', () => {
  const state = setup(true, false);
  assert.deepEqual(Object.keys(state.events), []);
  assert.equal(state.toggle.hidden, true);
});
