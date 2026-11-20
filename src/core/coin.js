export const defaultAssetDenom = "uclair";

export function parseCoin(value, defaultDenom = defaultAssetDenom) {
  const text = String(value || "").trim();
  const match = text.match(/^(0|[1-9][0-9]*)([a-zA-Z][a-zA-Z0-9/:._-]*)?$/);
  if (!match) {
    throw new Error(`invalid coin amount ${JSON.stringify(value)}`);
  }
  return {
    amount: match[1],
    denom: match[2] || defaultDenom,
    raw: `${match[1]}${match[2] || defaultDenom}`
  };
}
