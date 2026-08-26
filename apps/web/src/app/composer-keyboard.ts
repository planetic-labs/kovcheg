export interface ComposerKeyboardInput {
  readonly finePointer: boolean;
  readonly isComposing: boolean;
  readonly key: string;
  readonly shiftKey: boolean;
}

export function shouldSubmitComposerKey(input: ComposerKeyboardInput): boolean {
  return input.finePointer && !input.isComposing && input.key === 'Enter' && !input.shiftKey;
}
