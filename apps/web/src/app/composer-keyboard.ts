export interface ComposerKeyboardInput {
  readonly ctrlKey: boolean;
  readonly metaKey: boolean;
  readonly finePointer: boolean;
  readonly isComposing: boolean;
  readonly key: string;
  readonly shiftKey: boolean;
}

export function shouldSubmitComposerKey(input: ComposerKeyboardInput): boolean {
  return (
    input.finePointer &&
    !input.isComposing &&
    input.key === 'Enter' &&
    !input.shiftKey &&
    !input.ctrlKey &&
    !input.metaKey
  );
}
