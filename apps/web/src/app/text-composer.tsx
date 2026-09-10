'use client';

import { useEffect, useRef } from 'react';
import type { FormEvent } from 'react';

import { shouldSubmitComposerKey } from './composer-keyboard';

export function TextComposer({
  draft,
  onDraftChange,
  onSubmit,
}: Readonly<{
  draft: string;
  onDraftChange: (draft: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}>) {
  const input = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    function resize(): void {
      const element = input.current;
      if (element === null) return;
      element.style.height = '0px';
      element.style.height = `${element.scrollHeight}px`;
    }
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, [draft]);
  return (
    <form className="composer" onSubmit={onSubmit}>
      <label className="visually-hidden" htmlFor="message-draft">
        Текст сообщения
      </label>
      <textarea
        aria-describedby="composer-keyboard-hint"
        id="message-draft"
        maxLength={20_000}
        onChange={(event) => onDraftChange(event.currentTarget.value)}
        onKeyDown={(event) => {
          if (
            shouldSubmitComposerKey({
              finePointer: globalThis.matchMedia('(pointer: fine)').matches,
              isComposing: event.nativeEvent.isComposing || event.keyCode === 229,
              key: event.key,
              shiftKey: event.shiftKey,
            })
          ) {
            event.preventDefault();
            event.currentTarget.form?.requestSubmit();
          }
        }}
        placeholder="Написать сообщение"
        ref={input}
        rows={1}
        value={draft}
      />
      <div className="composer-actions">
        <div className="composer-tools" role="group" aria-label="Дополнения к сообщению">
          <button
            aria-label="Вложения — пока недоступно"
            className="composer-tool"
            disabled
            type="button"
          >
            <svg aria-hidden="true" viewBox="0 0 24 24">
              <path d="M12 5v14M5 12h14" />
            </svg>
          </button>
          <button
            aria-label="Стикеры — пока недоступно"
            className="composer-tool"
            disabled
            type="button"
          >
            <svg aria-hidden="true" viewBox="0 0 24 24">
              <path d="M6.8 3.5h7.6a4.1 4.1 0 0 1 4.1 4.1v6.1L12.2 20H7.6a4.1 4.1 0 0 1-4.1-4.1V6.8a3.3 3.3 0 0 1 3.3-3.3Z" />
              <path d="M12.2 20v-3.1a3.2 3.2 0 0 1 3.2-3.2h3.1" />
              <path d="M7.6 9.4h.1M13.6 9.4h.1M8.2 13.1c1.5 1.3 3.2 1.3 4.7 0" />
            </svg>
          </button>
          <button
            aria-label="Эмодзи — пока недоступно"
            className="composer-tool"
            disabled
            type="button"
          >
            <svg aria-hidden="true" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="8.5" />
              <path d="M8.8 10h.1M15.1 10h.1M8.8 14c1.8 1.7 4.6 1.7 6.4 0" />
            </svg>
          </button>
        </div>
        <div className="composer-tools" role="group" aria-label="Отправка сообщения">
          <button
            aria-label="Голосовое сообщение — пока недоступно"
            className="composer-tool"
            disabled
            type="button"
          >
            <svg aria-hidden="true" viewBox="0 0 24 24">
              <rect x="8.2" y="3.5" width="7.6" height="11.2" rx="3.8" />
              <path d="M5.8 11.7a6.2 6.2 0 0 0 12.4 0M12 17.9v2.6M8.8 20.5h6.4" />
            </svg>
          </button>
          <button
            aria-label="Видеосообщение — пока недоступно"
            className="composer-tool composer-tool-video"
            disabled
            type="button"
          >
            <svg aria-hidden="true" viewBox="0 0 28 28">
              <circle cx="14" cy="14" r="11.5" />
              <circle cx="12.1" cy="12" r="3.1" />
              <path d="m15.2 12.2 4-2.3v5.2l-4-2.2" />
            </svg>
          </button>
          <button
            aria-label="Отправить сообщение"
            className="send-button"
            disabled={draft.trim().length === 0}
            type="submit"
          />
        </div>
      </div>
      <span className="visually-hidden" id="composer-keyboard-hint">
        На компьютере Enter — отправить, Shift+Enter — новая строка. На телефоне Enter — новая
        строка.
      </span>
    </form>
  );
}
