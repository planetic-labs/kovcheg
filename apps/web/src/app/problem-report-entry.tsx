'use client';

import { useEffect, useId, useRef, useState } from 'react';
import type { KeyboardEvent, RefObject } from 'react';

import { normalizeProblemReportContext } from '../a6/problem-report-context';

interface ProblemReportDialogProps {
  readonly closeButtonRef?: RefObject<HTMLButtonElement | null>;
  readonly context?: unknown;
  readonly onClose: () => void;
  readonly titleId: string;
}

function ProblemReportDialog({
  closeButtonRef,
  context,
  onClose,
  titleId,
}: ProblemReportDialogProps) {
  const safeContext = normalizeProblemReportContext(context);
  const descriptionId = `${titleId}-description`;

  function keepFocusInside(event: KeyboardEvent<HTMLElement>): void {
    if (event.key !== 'Tab') return;
    event.preventDefault();
    closeButtonRef?.current?.focus();
  }

  return (
    <div
      className="problem-report-backdrop"
      onMouseDown={(event) => {
        if (event.currentTarget === event.target) onClose();
      }}
    >
      <section
        aria-describedby={descriptionId}
        aria-labelledby={titleId}
        aria-modal="true"
        className="problem-report-dialog"
        onKeyDown={keepFocusInside}
        role="dialog"
      >
        <p className="eyebrow">Помощь</p>
        <h2 id={titleId}>Сообщить о проблеме</h2>
        <p id={descriptionId}>
          Защищённая отправка будет подключена на этапе A7. Сейчас сведения не отправляются и не
          сохраняются.
        </p>
        {(safeContext.errorCode !== undefined || safeContext.correlationId !== undefined) && (
          <dl className="problem-report-context">
            {safeContext.errorCode !== undefined && (
              <div>
                <dt>Код ошибки</dt>
                <dd>{safeContext.errorCode}</dd>
              </div>
            )}
            {safeContext.correlationId !== undefined && (
              <div>
                <dt>Идентификатор обращения</dt>
                <dd>{safeContext.correlationId}</dd>
              </div>
            )}
          </dl>
        )}
        <button className="secondary-button" onClick={onClose} ref={closeButtonRef} type="button">
          Закрыть
        </button>
      </section>
    </div>
  );
}

export function ProblemReportEntry({ context }: Readonly<{ context?: unknown }>) {
  const [open, setOpen] = useState(false);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const detailsRef = useRef<HTMLDetailsElement>(null);
  const summaryRef = useRef<HTMLElement>(null);
  const titleId = useId();

  function close(): void {
    setOpen(false);
    requestAnimationFrame(() => summaryRef.current?.focus());
  }

  useEffect(() => {
    if (!open) return;
    closeButtonRef.current?.focus();

    function onKeyDown(event: globalThis.KeyboardEvent): void {
      if (event.key === 'Escape') close();
    }

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open]);

  return (
    <div className="problem-report-entry">
      <details ref={detailsRef}>
        <summary aria-label="Открыть помощь" ref={summaryRef}>
          Помощь
        </summary>
        <div className="help-menu-popover">
          <button
            onClick={() => {
              detailsRef.current?.removeAttribute('open');
              setOpen(true);
            }}
            type="button"
          >
            Сообщить о проблеме
          </button>
        </div>
      </details>
      {open && (
        <ProblemReportDialog
          closeButtonRef={closeButtonRef}
          context={context}
          onClose={close}
          titleId={titleId}
        />
      )}
    </div>
  );
}
