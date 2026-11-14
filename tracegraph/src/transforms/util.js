/** Builds one transform result: a related entity plus the label for the edge to it. */
export function ent(type, value, edge, props = {}) {
  return { type, value: String(value), edge, props };
}

/** Removes empty props (null/undefined/''/[]) so the details panel stays readable. */
export function clean(obj) {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && !v.length))
  );
}
