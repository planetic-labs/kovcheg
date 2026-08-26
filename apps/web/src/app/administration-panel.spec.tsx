import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const sourceUrl = new URL('./administration-panel.tsx', import.meta.url);

function attributeValues(markup: string, attribute: string): string[] {
  return Array.from(markup.matchAll(new RegExp(`\\s${attribute}="([^"]+)"`, 'gu')), (match) =>
    String(match[1]),
  );
}

describe('AdministrationPanel semantics', () => {
  it('gives each form instance its own field identifiers', async () => {
    const source = await readFile(sourceUrl, 'utf8');
    const fieldCalls = Array.from(source.matchAll(/<Field\b[\s\S]*?\/>/gu), (match) => match[0]);

    expect(fieldCalls).toHaveLength(9);
    for (const field of fieldCalls) expect(field).toMatch(/\bid=/u);
    expect(source).toContain("mode === 'create' ? 'account-create' : 'account-update'");
    expect(source).toContain('<AuthorizationFields idPrefix="domain-status" />');
    expect(source).toContain('<AuthorizationFields idPrefix="functional-grant" />');
    expect(source).not.toContain('field-${name}');
    expect(source).not.toContain('authorization-version');
  });

  it('associates every field and static control with exactly one label', async () => {
    const source = await readFile(sourceUrl, 'utf8');
    const literalIds = attributeValues(source, 'id');
    const literalLabelTargets = attributeValues(source, 'htmlFor');
    const literalControlIds = Array.from(
      source.matchAll(/<(?:input|select)\b[^>]*\sid="([^"]+)"[^>]*>/gu),
      (match) => String(match[1]),
    );

    expect(literalIds).toHaveLength(new Set(literalIds).size);
    for (const id of literalControlIds) {
      expect(literalLabelTargets.filter((target) => target === id)).toHaveLength(1);
    }
    expect(source).toContain('<label htmlFor={id}>{label}</label>');
    expect(source).toContain('<input id={id}');
    expect(source).toContain('<label htmlFor={versionId}>Следующая версия права</label>');
    expect(source).toContain('<input id={versionId}');
    expect(source).toContain('id: string;');
    expect(source).toContain('const versionId = `${idPrefix}-version`;');
  });
});
