import { describe, expect, it } from 'vitest';

import { shouldSubmitComposerKey } from './composer-keyboard';

describe('A6 desktop composer keyboard contract', () => {
  it('submits plain Enter only for a fine-pointer desktop context', () => {
    expect(
      shouldSubmitComposerKey({
        finePointer: true,
        isComposing: false,
        key: 'Enter',
        shiftKey: false,
      }),
    ).toBe(true);
  });

  it('keeps Shift+Enter as a newline and never submits during IME composition', () => {
    expect(
      shouldSubmitComposerKey({
        finePointer: true,
        isComposing: false,
        key: 'Enter',
        shiftKey: true,
      }),
    ).toBe(false);
    expect(
      shouldSubmitComposerKey({
        finePointer: true,
        isComposing: true,
        key: 'Enter',
        shiftKey: false,
      }),
    ).toBe(false);
  });

  it('does not turn Enter into submit on coarse-pointer mobile/touch input', () => {
    expect(
      shouldSubmitComposerKey({
        finePointer: false,
        isComposing: false,
        key: 'Enter',
        shiftKey: false,
      }),
    ).toBe(false);
  });
});
