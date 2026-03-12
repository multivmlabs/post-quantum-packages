import { readdir, readFile } from 'node:fs/promises';

const distUrl = new URL('../dist/', import.meta.url);
const entries = await readdir(distUrl, { withFileTypes: true });

const relativeSpecifierPattern =
  /(?:import|export)\s+(?:[^'"`]*?\sfrom\s*)?['"](\.{1,2}\/[^'"]+)['"]/g;

for (const entry of entries) {
  if (!entry.isFile() || !entry.name.endsWith('.js')) {
    continue;
  }

  const fileUrl = new URL(entry.name, distUrl);
  const source = await readFile(fileUrl, 'utf8');

  let match;
  while ((match = relativeSpecifierPattern.exec(source)) !== null) {
    const specifier = match[1];
    if (!specifier.endsWith('.js')) {
      throw new Error(
        `Dist smoke check failed: ${entry.name} contains non-.js relative import/export specifier '${specifier}'.`,
      );
    }
  }
}
