#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${PQ_OQS_IMAGE:-openquantumsafe/oqs-ossl3}"
OUT_DIR="${PQ_KEY_DIR:-/tmp/pq-key-encoder-realkeys}"
ALGS="${PQ_ALGS:-ML-DSA-65}"
NODE_BIN="${PQ_NODE_BIN:-node}"
BUN_BIN="${PQ_BUN_BIN:-bun}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to run this test."
  exit 1
fi

mkdir -p "$OUT_DIR"

run_ossl() {
  docker run --rm -v "$OUT_DIR:/work" -w /work "$IMAGE" "$@"
}

safe_name() {
  echo "$1" | tr 'A-Z' 'a-z' | sed -E 's/[^a-z0-9]+/_/g; s/^_+|_+$//g'
}

IFS=',' read -r -a ALG_LIST <<< "$ALGS"

echo "Using OpenSSL image: $IMAGE"
echo "Output directory: $OUT_DIR"
echo "Algorithms: $ALGS"

for alg in "${ALG_LIST[@]}"; do
  alg_trimmed="$(echo "$alg" | xargs)"
  if [ -z "$alg_trimmed" ]; then
    continue
  fi
  safe="$(safe_name "$alg_trimmed")"
  echo "Generating keys for $alg_trimmed..."

  run_ossl openssl genpkey -algorithm "$alg_trimmed" -provider oqsprovider -out "${safe}_priv.pem"
  run_ossl openssl pkey -in "${safe}_priv.pem" -pubout -out "${safe}_pub.pem" -provider oqsprovider
  run_ossl openssl pkey -in "${safe}_priv.pem" -outform DER -out "${safe}_priv.der" -provider oqsprovider
  run_ossl openssl pkey -in "${safe}_priv.pem" -pubout -outform DER -out "${safe}_pub.der" -provider oqsprovider
done

echo "Building pq-key-encoder..."
rm -rf "$ROOT_DIR/packages/pq-key-encoder/ts/dist" \
  "$ROOT_DIR/packages/pq-key-encoder/ts/tsconfig.tsbuildinfo"
(cd "$ROOT_DIR/packages/pq-key-encoder/ts" && npm run build -- --force)

echo "Re-encoding keys with pq-key-encoder..."
JS_BASE="$(mktemp -t pq-key-encoder-realkey-test)"
JS_TMP="${JS_BASE}.mjs"
mv "$JS_BASE" "$JS_TMP"
cat <<'NODE' > "$JS_TMP"
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.env.PQ_ROOT ?? process.cwd();
const outDir = process.env.PQ_KEY_DIR ?? '/tmp/pq-key-encoder-realkeys';
const algs = (process.env.PQ_ALGS ?? 'ML-DSA-65')
  .split(',')
  .map((alg) => alg.trim())
  .filter(Boolean);

const moduleUrl = new URL('packages/pq-key-encoder/ts/dist/index.js', `file://${root}/`);
const encoder = await import(moduleUrl.href);

const failures = [];

function safeName(alg) {
  return alg
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

for (const alg of algs) {
  const safe = safeName(alg);
  const pubDer = readFileSync(join(outDir, `${safe}_pub.der`));
  const privDer = readFileSync(join(outDir, `${safe}_priv.der`));
  const pubPem = readFileSync(join(outDir, `${safe}_pub.pem`), 'utf8');
  const privPem = readFileSync(join(outDir, `${safe}_priv.pem`), 'utf8');

  const pubKey = encoder.fromDER(new Uint8Array(pubDer));
  const privKey = encoder.fromDER(new Uint8Array(privDer));
  const pubKeyFromPem = encoder.fromPEM(pubPem);
  const privKeyFromPem = encoder.fromPEM(privPem);

  const rePubDer = encoder.toDER(pubKey);
  const rePrivDer = encoder.toDER(privKey);
  const rePubPem = encoder.toPEM(pubKey);
  const rePrivPem = encoder.toPEM(privKey);

  writeFileSync(join(outDir, `${safe}_pub_reencoded.der`), rePubDer);
  writeFileSync(join(outDir, `${safe}_priv_reencoded.der`), rePrivDer);
  writeFileSync(join(outDir, `${safe}_pub_reencoded.pem`), rePubPem);
  writeFileSync(join(outDir, `${safe}_priv_reencoded.pem`), rePrivPem);

  const jwkPublic = encoder.toJWK(pubKey);
  const jwkPrivate = encoder.toJWK(privKey, {
    includePrivate: true,
    publicKey: pubKey.bytes,
  });
  writeFileSync(join(outDir, `${safe}_pub.jwk.json`), JSON.stringify(jwkPublic, null, 2));
  writeFileSync(join(outDir, `${safe}_priv.jwk.json`), JSON.stringify(jwkPrivate, null, 2));

  const roundPub = encoder.fromJWK(jwkPublic);
  const roundPriv = encoder.fromJWK(jwkPrivate);

  if (Buffer.compare(Buffer.from(roundPub.bytes), Buffer.from(pubKey.bytes)) !== 0) {
    failures.push(`${alg}: public JWK round-trip mismatch`);
  }
  if (Buffer.compare(Buffer.from(roundPriv.bytes), Buffer.from(privKey.bytes)) !== 0) {
    failures.push(`${alg}: private JWK round-trip mismatch`);
  }
  if (Buffer.compare(Buffer.from(pubKeyFromPem.bytes), Buffer.from(pubKey.bytes)) !== 0) {
    failures.push(`${alg}: public PEM parse mismatch`);
  }
  if (Buffer.compare(Buffer.from(privKeyFromPem.bytes), Buffer.from(privKey.bytes)) !== 0) {
    failures.push(`${alg}: private PEM parse mismatch`);
  }

}

if (failures.length > 0) {
  console.error('Failures:');
  for (const item of failures) {
    console.error(`- ${item}`);
  }
  process.exit(1);
}
NODE

if command -v "$BUN_BIN" >/dev/null 2>&1; then
  PQ_ROOT="$ROOT_DIR" PQ_KEY_DIR="$OUT_DIR" PQ_ALGS="$ALGS" "$BUN_BIN" "$JS_TMP"
elif command -v "$NODE_BIN" >/dev/null 2>&1; then
  PQ_ROOT="$ROOT_DIR" PQ_KEY_DIR="$OUT_DIR" PQ_ALGS="$ALGS" "$NODE_BIN" \
    --experimental-specifier-resolution=node "$JS_TMP"
else
  echo "node or bun is required to run the re-encode step."
  rm -f "$JS_TMP"
  exit 1
fi

rm -f "$JS_TMP"

echo "Verifying re-encoded outputs with OpenSSL..."
for alg in "${ALG_LIST[@]}"; do
  alg_trimmed="$(echo "$alg" | xargs)"
  if [ -z "$alg_trimmed" ]; then
    continue
  fi
  safe="$(safe_name "$alg_trimmed")"

  run_ossl openssl pkey -pubin -in "${safe}_pub_reencoded.pem" -pubout -out /dev/null -provider oqsprovider
  run_ossl openssl pkey -in "${safe}_priv_reencoded.pem" -out /dev/null -provider oqsprovider
  run_ossl openssl pkey -pubin -in "${safe}_pub_reencoded.der" -inform DER -pubout -out /dev/null -provider oqsprovider
  run_ossl openssl pkey -in "${safe}_priv_reencoded.der" -inform DER -out /dev/null -provider oqsprovider
done

echo "All checks passed."
