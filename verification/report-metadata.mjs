import { collectExecutionMetadata, readJson, writeJson } from './lib.mjs';

const baseline = await readJson('verification/baseline.json');
const exceptions = await readJson('verification/exceptions.json');
const deferredProfiles = await readJson('verification/profiles.json');
const knipBaseline = await readJson('verification/knip-baseline.json');

await writeJson('.artifacts/verification/deep/metadata.json', {
  ...(await collectExecutionMetadata()),
  baseline,
  deferredProfiles,
  exceptions,
  knipBaseline,
  status: 'INFORMATIONAL',
});

console.log(
  `Recorded baseline, ${exceptions.exceptions.length} narrow exceptions, and ${deferredProfiles.profiles.length} deferred profile classifications.`,
);
