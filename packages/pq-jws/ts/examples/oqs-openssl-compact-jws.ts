import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseJwsCompact } from '../src/compact';
import { decodePayloadJson, signJwsCompact, verifyJwsCompact } from '../src/index';

const OQS_IMAGE =
  process.env.OQS_OPENSSL_IMAGE ??
  'openquantumsafe/oqs-ossl3@sha256:48b586a2734452fcaff76bad81cba63d37bc8410510e05a40674b450c0ded559';
const SHOULD_CLEANUP = process.env.CLEANUP_EXAMPLE_ARTIFACTS === '1';
const ALGORITHM = 'ML-DSA-87';

type DockerResult = {
  status: number;
  stdout: string;
  stderr: string;
};

function runOqsOpenSsl(artifactDir: string, args: string[]): DockerResult {
  const result = spawnSync(
    'docker',
    ['run', '--rm', '-v', `${artifactDir}:/work`, '-w', '/work', OQS_IMAGE, 'openssl', ...args],
    {
      encoding: 'utf8',
    },
  );

  return {
    status: result.status ?? 1,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function assertSuccess(operation: string, result: DockerResult): void {
  if (result.status === 0) {
    return;
  }

  throw new Error(
    [
      `${operation} failed with exit code ${result.status}.`,
      `stdout:\n${result.stdout || '<empty>'}`,
      `stderr:\n${result.stderr || '<empty>'}`,
    ].join('\n\n'),
  );
}

function generateKeypair(artifactDir: string, prefix: string, algorithm: string): void {
  assertSuccess(
    `key generation (${algorithm})`,
    runOqsOpenSsl(artifactDir, [
      'genpkey',
      '-algorithm',
      algorithm,
      '-out',
      `${prefix}-private.pem`,
    ]),
  );

  assertSuccess(
    `public key derivation (${algorithm})`,
    runOqsOpenSsl(artifactDir, [
      'pkey',
      '-in',
      `${prefix}-private.pem`,
      '-pubout',
      '-out',
      `${prefix}-public.pem`,
    ]),
  );
}

async function main(): Promise<void> {
  const artifactDir = mkdtempSync(join(tmpdir(), 'pq-jws-real-app-'));

  try {
    generateKeypair(artifactDir, 'signer', ALGORITHM);
    generateKeypair(artifactDir, 'mismatch', ALGORITHM);

    const payload = {
      sub: 'user-123',
      role: 'admin',
      scope: ['read:orders', 'write:orders'],
      iat: Math.floor(Date.now() / 1000),
    };

    const compact = await signJwsCompact({
      protectedHeader: {
        alg: ALGORITHM,
        kid: 'signer-1',
        typ: 'JWT',
      },
      payload: JSON.stringify(payload),
      signer: async (signingInput) => {
        const signingInputPath = join(artifactDir, 'signing-input.bin');
        const signaturePath = join(artifactDir, 'signature.bin');

        writeFileSync(signingInputPath, signingInput);
        assertSuccess(
          'signing operation',
          runOqsOpenSsl(artifactDir, [
            'pkeyutl',
            '-sign',
            '-inkey',
            'signer-private.pem',
            '-in',
            'signing-input.bin',
            '-out',
            'signature.bin',
          ]),
        );

        return new Uint8Array(readFileSync(signaturePath));
      },
    });

    const parsed = parseJwsCompact(compact);
    const claims = decodePayloadJson<typeof payload>(parsed);

    const verified = await verifyJwsCompact(compact, async (signingInput, signature) => {
      writeFileSync(join(artifactDir, 'verify-input.bin'), signingInput);
      writeFileSync(join(artifactDir, 'verify-signature.bin'), signature);

      const result = runOqsOpenSsl(artifactDir, [
        'pkeyutl',
        '-verify',
        '-pubin',
        '-inkey',
        'signer-public.pem',
        '-in',
        'verify-input.bin',
        '-sigfile',
        'verify-signature.bin',
      ]);

      return result.status === 0;
    });

    const wrongKeyVerification = await verifyJwsCompact(
      compact,
      async (signingInput, signature) => {
        writeFileSync(join(artifactDir, 'wrong-verify-input.bin'), signingInput);
        writeFileSync(join(artifactDir, 'wrong-verify-signature.bin'), signature);

        const result = runOqsOpenSsl(artifactDir, [
          'pkeyutl',
          '-verify',
          '-pubin',
          '-inkey',
          'mismatch-public.pem',
          '-in',
          'wrong-verify-input.bin',
          '-sigfile',
          'wrong-verify-signature.bin',
        ]);

        return result.status === 0;
      },
    );

    const tampered = `${parsed.encodedProtectedHeader}.ZXlKMGJIQWlPaUpLVjFRaWZRLg.${parsed.segments.signature}`;
    const tamperedVerified = await verifyJwsCompact(tampered, async (signingInput, signature) => {
      writeFileSync(join(artifactDir, 'tampered-input.bin'), signingInput);
      writeFileSync(join(artifactDir, 'tampered-signature.bin'), signature);

      const result = runOqsOpenSsl(artifactDir, [
        'pkeyutl',
        '-verify',
        '-pubin',
        '-inkey',
        'signer-public.pem',
        '-in',
        'tampered-input.bin',
        '-sigfile',
        'tampered-signature.bin',
      ]);

      return result.status === 0;
    });

    console.log('Compact JWS (truncated):', `${compact.slice(0, 96)}...`);
    console.log('Decoded claims:', claims);
    console.log('Verification (matching public key):', verified);
    console.log('Verification (wrong public key):', wrongKeyVerification);
    console.log('Verification (tampered payload):', tamperedVerified);
    console.log('Artifacts directory:', artifactDir);
    console.log('Generated artifacts:');
    console.log('- signer-private.pem / signer-public.pem');
    console.log('- mismatch-private.pem / mismatch-public.pem');
    console.log('- signing-input.bin / signature.bin');
    console.log('- verify-input.bin / verify-signature.bin');
    console.log('- wrong-verify-input.bin / wrong-verify-signature.bin');
    console.log('- tampered-input.bin / tampered-signature.bin');
  } finally {
    if (SHOULD_CLEANUP) {
      rmSync(artifactDir, { recursive: true, force: true });
    }
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
