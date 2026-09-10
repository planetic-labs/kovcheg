import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import { describe, expect, it } from 'vitest';
import { TextComposer } from './text-composer';

const assetUrl = new URL('../../public/SERDTsA.png', import.meta.url);

describe('A6 visible send control', () => {
  it('keeps the approved public asset byte-identical', async () => {
    const asset = await readFile(assetUrl);
    expect(createHash('sha256').update(asset).digest('hex')).toBe(
      '0198fab41da9b42c464f0997682365df112b690a716f45bd386c2c82dbcf2182',
    );
  });

  it.each(['', '   ', 'synthetic text'])(
    'renders two action groups and safe draft controls for %j',
    (draft) => {
      const markup = renderToStaticMarkup(
        createElement(TextComposer, {
          draft,
          onDraftChange: () => undefined,
          onSubmit: () => undefined,
        }),
      );
      const buttons = [...markup.matchAll(/<button\b[^>]*>/gu)].map((match) => match[0]);
      expect(buttons).toHaveLength(6);
      for (const button of buttons.slice(0, 5)) {
        expect(button).toContain('disabled=""');
        expect(button).toContain('type="button"');
        expect(button).toContain('пока недоступно');
      }
      expect(buttons[5]).toContain('type="submit"');
      expect(buttons[5]?.includes('disabled=""')).toBe(draft.trim().length === 0);
      expect(markup.match(/role="group"/gu)).toHaveLength(2);
      expect(markup.indexOf('</textarea>')).toBeLessThan(
        markup.indexOf('class="composer-actions"'),
      );
      expect(markup).toContain('for="message-draft"');
      expect(markup).toContain('aria-describedby="composer-keyboard-hint"');
    },
  );
});
