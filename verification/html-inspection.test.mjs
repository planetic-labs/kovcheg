import assert from 'node:assert/strict';
import test from 'node:test';

import { attributeValue, openingTags } from '../infra/scripts/html-inspection.mjs';

test('extracts exact opening tags without treating quoted greater-than signs as boundaries', () => {
  const html = [
    '<script data-value=">" nonce="first">one</script>',
    '<scripture nonce="wrong"></scripture>',
    '<SCRIPT nonce=second src="/asset.js"></SCRIPT>',
    '<style nonce="style-value">body { color: black; }</style>',
  ].join('');

  const scripts = openingTags(html, 'script');
  assert.equal(scripts.length, 2);
  assert.equal(attributeValue(scripts[0], 'nonce'), 'first');
  assert.equal(attributeValue(scripts[1], 'NONCE'), 'second');
  assert.equal(attributeValue(openingTags(html, 'style')[0], 'nonce'), 'style-value');
});

test('fails closed for malformed or missing attributes', () => {
  assert.deepEqual(openingTags('<script nonce="unterminated', 'script'), []);
  assert.equal(attributeValue('<script src="/asset.js">', 'nonce'), null);
});
