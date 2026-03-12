const MAX_VALUE_PREVIEW_CHARS = 200;

function truncatePreview(value: string): string {
  if (value.length <= MAX_VALUE_PREVIEW_CHARS) {
    return value;
  }

  return `${value.slice(0, MAX_VALUE_PREVIEW_CHARS)}...<${value.length} chars total>`;
}

export function escapeStringForMessage(value: string): string {
  return truncatePreview(value).replace(/['\\\u0000-\u001f\u007f\u2028\u2029]/g, (character) => {
    switch (character) {
      case "'":
        return "\\'";
      case '\\':
        return '\\\\';
      case '\n':
        return '\\n';
      case '\r':
        return '\\r';
      case '\t':
        return '\\t';
      case '\u0000':
        return '\\0';
      default: {
        const codePoint = character.charCodeAt(0);
        if (codePoint <= 0xff) {
          return `\\x${codePoint.toString(16).padStart(2, '0')}`;
        }
        return `\\u${codePoint.toString(16).padStart(4, '0')}`;
      }
    }
  });
}

export function describePropertyKey(propertyKey: string | symbol): string {
  if (typeof propertyKey === 'string') {
    return escapeStringForMessage(propertyKey);
  }
  return escapeStringForMessage(String(propertyKey));
}

export function describeUnknownValue(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'string':
      return escapeStringForMessage(value);
    case 'number':
    case 'boolean':
    case 'undefined':
      return String(value);
    case 'bigint':
      return truncatePreview(String(value));
    case 'symbol':
      return escapeStringForMessage(String(value));
    default:
      return `<${typeof value}>`;
  }
}
