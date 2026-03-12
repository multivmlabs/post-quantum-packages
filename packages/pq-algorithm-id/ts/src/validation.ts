import { InvalidArgumentError } from './errors.js';
import { describeUnknownValue } from './value-format.js';

export function assertAlgorithmNameInput(name: unknown): asserts name is string {
  if (typeof name === 'string') {
    return;
  }

  throw new InvalidArgumentError(
    'name',
    `Expected algorithm name to be a string, received '${describeUnknownValue(name)}'.`,
  );
}
