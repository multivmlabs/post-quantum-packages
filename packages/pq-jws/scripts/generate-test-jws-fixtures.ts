import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

type InvalidVariantFixture = {
  id: string;
  compact: string;
  expectedFailure: 'signature_mismatch' | 'format_error';
};

type ValidFixture = {
  id: string;
  algorithm: string;
  protectedHeader: Record<string, unknown>;
  payload: Record<string, unknown>;
  compact: string;
  signingInput: string;
  encodedProtectedHeader: string;
  encodedPayload: string;
  signatureBase64Url: string;
  verificationMaterial: {
    publicKeyPem: string;
    publicKeyDerBase64: string;
    provider: string;
  };
  invalidVariants: InvalidVariantFixture[];
};

type FixtureTemplate = {
  metadata: {
    generatedAt: string;
    source: {
      backend: string;
      image: string;
      commandSet: string[];
      deterministicControls: {
        canonicalFixtureOrdering: boolean;
        seedMode: string;
        note: string;
      };
    };
  };
  fixtures: ValidFixture[];
};

type FixtureManifest = {
  schemaVersion: 1;
  generatedBy: string;
  fixtureFile: string;
  fixtureSha256: string;
  fixtureCount: number;
  invalidVariantCount: number;
  generationModel: string;
  deterministicControls: {
    canonicalFixtureOrdering: boolean;
    seedMode: string;
    note: string;
  };
  source: {
    backend: string;
    image: string;
    commandSet: string[];
    capturedAt: string;
  };
};

const scriptDir = dirname(new URL(import.meta.url).pathname);
const sourcePath = resolve(scriptDir, 'test-jws-source-fixtures.json');
const outputDir = resolve(scriptDir, '../test-data/test-jws');
const outputFixturePath = resolve(outputDir, 'fixtures.json');
const outputManifestPath = resolve(outputDir, 'manifest.json');

function stableSortFixtures(fixtures: ValidFixture[]): ValidFixture[] {
  return fixtures
    .map((fixture) => ({
      ...fixture,
      invalidVariants: [...fixture.invalidVariants].sort((a, b) => a.id.localeCompare(b.id)),
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

function renderFixtureJson(template: FixtureTemplate): string {
  const sortedTemplate: FixtureTemplate = {
    ...template,
    fixtures: stableSortFixtures(template.fixtures),
  };
  return `${JSON.stringify(sortedTemplate, null, 2)}\n`;
}

function createManifest(template: FixtureTemplate, fixtureSha256: string): FixtureManifest {
  const fixtureCount = template.fixtures.length;
  const invalidVariantCount = template.fixtures.reduce(
    (count, fixture) => count + fixture.invalidVariants.length,
    0,
  );

  return {
    schemaVersion: 1,
    generatedBy: 'packages/pq-jws/scripts/generate-test-jws-fixtures.ts',
    fixtureFile: 'fixtures.json',
    fixtureSha256,
    fixtureCount,
    invalidVariantCount,
    generationModel: 'template-replay',
    deterministicControls: {
      canonicalFixtureOrdering: template.metadata.source.deterministicControls.canonicalFixtureOrdering,
      seedMode: template.metadata.source.deterministicControls.seedMode,
      note: template.metadata.source.deterministicControls.note,
    },
    source: {
      backend: template.metadata.source.backend,
      image: template.metadata.source.image,
      commandSet: template.metadata.source.commandSet,
      capturedAt: template.metadata.generatedAt,
    },
  };
}

function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

function run(checkOnly: boolean): void {
  const template = JSON.parse(readFileSync(sourcePath, 'utf8')) as FixtureTemplate;
  const fixtureJson = renderFixtureJson(template);
  const fixtureSha256 = sha256(fixtureJson);
  const manifestJson = `${JSON.stringify(createManifest(template, fixtureSha256), null, 2)}\n`;

  if (checkOnly) {
    const existingFixture = readFileSync(outputFixturePath, 'utf8');
    const existingManifest = readFileSync(outputManifestPath, 'utf8');

    if (existingFixture !== fixtureJson) {
      throw new Error('fixtures.json is out of date. Run fixture generator without --check.');
    }

    if (existingManifest !== manifestJson) {
      throw new Error('manifest.json is out of date. Run fixture generator without --check.');
    }

    console.log('Fixtures are up to date.');
    return;
  }

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(outputFixturePath, fixtureJson);
  writeFileSync(outputManifestPath, manifestJson);
  console.log(`Wrote ${outputFixturePath}`);
  console.log(`Wrote ${outputManifestPath}`);
}

run(process.argv.includes('--check'));
