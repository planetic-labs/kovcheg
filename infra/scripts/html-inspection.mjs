function isNameCharacter(character) {
  return character !== undefined && /[A-Za-z0-9:_-]/u.test(character);
}

export function openingTags(html, expectedName) {
  const normalizedName = expectedName.toLowerCase();
  const tags = [];
  let cursor = 0;

  while (cursor < html.length) {
    const start = html.indexOf('<', cursor);
    if (start < 0) break;
    let index = start + 1;
    if (html[index] === '/' || html[index] === '!' || html[index] === '?') {
      cursor = index + 1;
      continue;
    }
    const nameStart = index;
    while (isNameCharacter(html[index])) index += 1;
    const name = html.slice(nameStart, index).toLowerCase();
    if (name !== normalizedName) {
      cursor = index + 1;
      continue;
    }

    let quote = null;
    while (index < html.length) {
      const character = html[index];
      if (quote !== null) {
        if (character === quote) quote = null;
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === '>') {
        tags.push(html.slice(start, index + 1));
        cursor = index + 1;
        break;
      }
      index += 1;
    }
    if (index >= html.length) break;
  }

  return tags;
}

export function attributeValue(openingTag, expectedName) {
  const normalizedName = expectedName.toLowerCase();
  let index = 1;
  while (isNameCharacter(openingTag[index])) index += 1;

  while (index < openingTag.length) {
    while (/\s/u.test(openingTag[index] ?? '')) index += 1;
    if (openingTag[index] === '>' || openingTag[index] === '/') break;
    const nameStart = index;
    while (isNameCharacter(openingTag[index])) index += 1;
    const name = openingTag.slice(nameStart, index).toLowerCase();
    while (/\s/u.test(openingTag[index] ?? '')) index += 1;
    if (openingTag[index] !== '=') {
      if (name === normalizedName) return '';
      continue;
    }
    index += 1;
    while (/\s/u.test(openingTag[index] ?? '')) index += 1;
    const quote = openingTag[index];
    let value;
    if (quote === '"' || quote === "'") {
      index += 1;
      const valueStart = index;
      while (index < openingTag.length && openingTag[index] !== quote) index += 1;
      value = openingTag.slice(valueStart, index);
      index += 1;
    } else {
      const valueStart = index;
      while (
        index < openingTag.length &&
        !/\s/u.test(openingTag[index] ?? '') &&
        openingTag[index] !== '>'
      ) {
        index += 1;
      }
      value = openingTag.slice(valueStart, index);
    }
    if (name === normalizedName) return value;
  }

  return null;
}
