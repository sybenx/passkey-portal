import { test } from 'node:test';
import assert from 'node:assert/strict';
import { originList, lists, portalsFrom, tryPortals } from '../js/portals.js';
import shipped from '../mirrors.js';

const A = 'https://a.example', B = 'https://b.example', C = 'https://c.example';

test('the mirror list keeps valid origins in order, drops junk, repeats and itself', () => {
  assert.deepEqual(originList([B, 'http://x.example', A, B, 'https://c.example/', 42, C], A), [B, C]);
  assert.deepEqual(originList(undefined), []);
  assert.deepEqual(originList({ mirrors: [B] }), []);
  assert.deepEqual(originList(['http://localhost:8000', 'http://127.0.0.1:8001']), ['http://localhost:8000', 'http://127.0.0.1:8001']);
  assert.ok(Array.isArray(shipped), 'mirrors.js exports a list');
  assert.deepEqual(originList(['http://b.localhost:8001', 'http://localhost.example', 'http://b.localhost.example']), ['http://b.localhost:8001'], '*.localhost for testing, nothing like it');
});

test('mutual listing: each side must name the other', () => {
  const aList = [B], bList = [A], cList = [B];
  assert.equal(lists(aList, B) && lists(bList, A), true, 'A and B list each other');
  assert.equal(lists(aList, C), false, 'A will not offer to C');
  assert.equal(lists(bList, C), false, 'B will not accept from C, though C lists B');
  assert.equal(lists(cList, B), true);
  assert.equal(lists([B + '/'], B), false, 'only exact origins count');
});

test('the portals a site tries come from ?portal=, in order', () => {
  assert.deepEqual(portalsFrom('?portal=' + A + '&portal=' + B, 'https://here.example'), [A, B]);
  assert.deepEqual(portalsFrom('?portal=' + encodeURIComponent(`${B}, ${A}`), 'https://here.example'), [B, A]);
  assert.deepEqual(portalsFrom('?portal=http://evil.example&portal=' + A, 'https://here.example'), [A]);
  assert.deepEqual(portalsFrom('', 'https://here.example'), ['https://here.example']);
  assert.deepEqual(portalsFrom('?portal=junk', 'https://here.example'), ['https://here.example']);
});

test('falling through: ask the first, move on after the wait, stop when one answers', () => {
  const r = tryPortals([A, B, C], 0, 5000);
  assert.equal(r.current, A);
  assert.equal(r.tick(250), 'ask');
  assert.equal(r.tick(4999), 'ask');
  assert.equal(r.tick(5000), 'next'); assert.equal(r.current, B);
  assert.equal(r.tick(5250), 'ask');
  r.ready();
  assert.equal(r.tick(60000), 'wait'); assert.equal(r.current, B, 'an answering portal is kept, however long the person takes');
});

test('falling through: gives up after the last', () => {
  const r = tryPortals([A, B], 0, 1000);
  assert.equal(r.tick(1000), 'next');
  assert.equal(r.tick(1999), 'ask');
  assert.equal(r.tick(2000), 'give-up');
  assert.equal(r.tick(9000), 'give-up');
  assert.equal(r.current, B);
});
