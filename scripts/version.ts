import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { $ } from "bun";

const PACKAGES_DIR = "packages";
const VALID_LANGUAGES = ["ts", "rust", "python"] as const;
const VALID_BUMPS = ["major", "minor", "patch"] as const;

type Language = (typeof VALID_LANGUAGES)[number];
type Bump = (typeof VALID_BUMPS)[number];

function parseArgs(): { package: string; language: Language; bump: Bump } {
	const args = process.argv.slice(2);

	if (args.length < 2) {
		console.error(
			"Usage: bun version <package>/<language> <major|minor|patch>",
		);
		console.warn(`Example: 
      bun version pq-oid/ts patch       # 0.0.1 -> 0.0.2
      bun version pq-oid/ts minor       # 0.0.1 -> 0.1.0
      bun version pq-oid/ts major       # 0.0.1 -> 1.0.0
      bun version pq-oid/rust patch     # bumps Cargo.toml
      bun version pq-oid/python minor   # bumps pyproject.toml`);
		process.exit(1);
	}

	const [target, bump] = args;
	const [pkg, lang] = target.split("/");

	if (!pkg || !lang) {
		console.error(`Invalid target: ${target}`);
		console.error("Expected format: <package>/<language> (e.g., pq-oid/ts)");
		process.exit(1);
	}

	if (!VALID_LANGUAGES.includes(lang as Language)) {
		console.error(`Invalid language: ${lang}`);
		console.error(`Valid languages: ${VALID_LANGUAGES.join(", ")}`);
		process.exit(1);
	}

	if (!VALID_BUMPS.includes(bump as Bump)) {
		console.error(`Invalid bump type: ${bump}`);
		console.error(`Valid bump types: ${VALID_BUMPS.join(", ")}`);
		process.exit(1);
	}

	return { package: pkg, language: lang as Language, bump: bump as Bump };
}

function bumpVersion(version: string, bump: Bump): string {
	const parts = version.split(".").map(Number);
	if (parts.length !== 3 || parts.some(Number.isNaN)) {
		throw new Error(`Invalid semver version: ${version}`);
	}

	const [major, minor, patch] = parts;

	switch (bump) {
		case "major":
			return `${major + 1}.0.0`;
		case "minor":
			return `${major}.${minor + 1}.0`;
		case "patch":
			return `${major}.${minor}.${patch + 1}`;
	}
}

async function getVersionTs(dir: string): Promise<string> {
	const pkgPath = join(dir, "package.json");
	const content = await readFile(pkgPath, "utf-8");
	const pkg = JSON.parse(content);
	return pkg.version;
}

async function setVersionTs(dir: string, version: string): Promise<void> {
	const pkgPath = join(dir, "package.json");
	const content = await readFile(pkgPath, "utf-8");
	const pkg = JSON.parse(content);
	pkg.version = version;
	await writeFile(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
}

async function getVersionRust(dir: string): Promise<string> {
	const cargoPath = join(dir, "Cargo.toml");
	const content = await readFile(cargoPath, "utf-8");
	const match = content.match(/^version\s*=\s*"([^"]+)"/m);
	if (!match) {
		throw new Error(`Could not find version in ${cargoPath}`);
	}
	return match[1];
}

async function setVersionRust(dir: string, version: string): Promise<void> {
	const cargoPath = join(dir, "Cargo.toml");
	const content = await readFile(cargoPath, "utf-8");
	const updated = content.replace(
		/^(version\s*=\s*)"[^"]+"/m,
		`$1"${version}"`,
	);
	await writeFile(cargoPath, updated);
}

async function getVersionPython(dir: string): Promise<string> {
	const pyprojectPath = join(dir, "pyproject.toml");
	const content = await readFile(pyprojectPath, "utf-8");
	const match = content.match(/^version\s*=\s*"([^"]+)"/m);
	if (!match) {
		throw new Error(`Could not find version in ${pyprojectPath}`);
	}
	return match[1];
}

async function setVersionPython(dir: string, version: string): Promise<void> {
	const pyprojectPath = join(dir, "pyproject.toml");
	const content = await readFile(pyprojectPath, "utf-8");
	const updated = content.replace(
		/^(version\s*=\s*)"[^"]+"/m,
		`$1"${version}"`,
	);
	await writeFile(pyprojectPath, updated);
}

const versionHandlers: Record<
	Language,
	{
		getVersion: (dir: string) => Promise<string>;
		setVersion: (dir: string, version: string) => Promise<void>;
		file: string;
	}
> = {
	ts: {
		getVersion: getVersionTs,
		setVersion: setVersionTs,
		file: "package.json",
	},
	rust: {
		getVersion: getVersionRust,
		setVersion: setVersionRust,
		file: "Cargo.toml",
	},
	python: {
		getVersion: getVersionPython,
		setVersion: setVersionPython,
		file: "pyproject.toml",
	},
};

async function main() {
	const { package: pkg, language, bump } = parseArgs();

	const dir = join(PACKAGES_DIR, pkg, language);

	if (!existsSync(dir)) {
		console.error(`Package directory not found: ${dir}`);
		process.exit(1);
	}

	const handler = versionHandlers[language];
	const configFile = join(dir, handler.file);

	if (!existsSync(configFile)) {
		console.error(`Config file not found: ${configFile}`);
		process.exit(1);
	}

	// Get current version
	const currentVersion = await handler.getVersion(dir);
	const newVersion = bumpVersion(currentVersion, bump);
	const tag = `${pkg}/${language}@${newVersion}`;

	console.log(`Package: ${pkg}/${language}`);
	console.log(`Version: ${currentVersion} -> ${newVersion}`);
	console.log(`Tag: ${tag}`);
	console.log();

	// Update version file
	await handler.setVersion(dir, newVersion);
	console.log(`Updated ${handler.file}`);

	// Git operations
	await $`git add ${configFile}`;
	await $`git commit -m "chore(${pkg}): bump ${language} version to ${newVersion}"`;
	console.log("Created commit");

	await $`git tag ${tag}`;
	console.log(`Created tag: ${tag}`);

	console.log();
	console.log("To publish, run:");
	console.log(`  git push origin HEAD ${tag}`);
}

main().catch((err) => {
	console.error(err.message);
	process.exit(1);
});
