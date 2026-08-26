'use client';

import { useRef } from 'react';
import type { ClipboardEvent, KeyboardEvent } from 'react';

interface CodeInputProps {
  readonly descriptionId?: string;
  readonly disabled?: boolean;
  readonly invalid?: boolean;
  readonly onChange: (digits: readonly string[]) => void;
}

const codeLength = 6;

export function CodeInput({
  descriptionId,
  disabled = false,
  invalid = false,
  onChange,
}: CodeInputProps) {
  const inputs = useRef<Array<HTMLInputElement | null>>([]);

  function currentDigits(): readonly string[] {
    return Object.freeze(inputs.current.map((input) => input?.value ?? ''));
  }

  function replaceDigit(index: number, input: HTMLInputElement): void {
    const digit = input.value.replace(/\D/gu, '').slice(-1);
    input.value = digit;
    onChange(currentDigits());
    if (digit.length === 1 && index < codeLength - 1) {
      inputs.current[index + 1]?.focus();
    }
  }

  function paste(event: ClipboardEvent<HTMLInputElement>): void {
    const pasted = event.clipboardData.getData('text').replace(/\D/gu, '').slice(0, codeLength);
    if (pasted.length === 0) {
      return;
    }
    event.preventDefault();
    for (let index = 0; index < codeLength; index += 1) {
      const input = inputs.current[index];
      if (input !== null && input !== undefined) {
        input.value = pasted[index] ?? '';
      }
    }
    onChange(currentDigits());
    inputs.current[Math.min(pasted.length, codeLength) - 1]?.focus();
  }

  function keyDown(index: number, event: KeyboardEvent<HTMLInputElement>): void {
    if (event.key === 'Backspace' && event.currentTarget.value === '' && index > 0) {
      inputs.current[index - 1]?.focus();
    }
    if (event.key === 'ArrowLeft' && index > 0) {
      inputs.current[index - 1]?.focus();
    }
    if (event.key === 'ArrowRight' && index < codeLength - 1) {
      inputs.current[index + 1]?.focus();
    }
  }

  return (
    <div
      aria-busy={disabled}
      aria-describedby={descriptionId}
      aria-label="Шестизначный код"
      className="code-grid"
      role="group"
    >
      {Array.from({ length: codeLength }, (_, index) => (
        <input
          aria-describedby={descriptionId}
          aria-invalid={invalid}
          aria-label={`Цифра ${index + 1}`}
          autoFocus={index === 0}
          autoComplete="off"
          className="code-slot"
          disabled={disabled}
          inputMode="numeric"
          key={index}
          maxLength={1}
          onChange={(event) => replaceDigit(index, event.currentTarget)}
          onKeyDown={(event) => keyDown(index, event)}
          onPaste={paste}
          pattern="[0-9]"
          ref={(element) => {
            inputs.current[index] = element;
          }}
          type="text"
        />
      ))}
    </div>
  );
}
