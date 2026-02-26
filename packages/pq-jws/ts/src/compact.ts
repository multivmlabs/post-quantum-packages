import { JwsError } from './errors';
import type { ParsedCompactJws } from './types';

export function parseJwsCompact(_compact: string): ParsedCompactJws {
  throw new JwsError('parseJwsCompact is not implemented yet.');
}
