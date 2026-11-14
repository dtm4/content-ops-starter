import { rdapTransforms } from './rdap.js';
import { dnsTransforms } from './dns.js';
import { webTransforms } from './web.js';
import { apiTransforms } from './apis.js';

// Infrastructure transforms that depend on the network come from separate modules
// so each can be unit tested with a mocked fetch.
export const transforms = [...dnsTransforms, ...rdapTransforms, ...webTransforms, ...apiTransforms];

export function getTransform(id) {
  return transforms.find((t) => t.id === id);
}

/** Env vars a transform still needs; empty array means it can run. */
export function missingKeys(t, env = process.env) {
  return (t.requires || []).filter((k) => !env[k]);
}

export function describeTransforms(env = process.env) {
  return transforms.map((t) => ({
    id: t.id,
    name: t.name,
    input: t.input,
    group: t.id.split('.')[0],
    requires: t.requires || [],
    available: missingKeys(t, env).length === 0
  }));
}
