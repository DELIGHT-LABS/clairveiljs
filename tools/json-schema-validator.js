/**
 * Small draft-2020-12 subset used by Clairveil's published wallet contract.
 * Keeping it local makes the release gate deterministic without pulling a
 * runtime dependency into the browser SDK.
 */
function typeMatches(value, type) {
  if (type === "array") return Array.isArray(value);
  if (type === "object") return Boolean(value) && typeof value === "object" && !Array.isArray(value);
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "null") return value === null;
  return typeof value === type;
}

function resolveReference(root, reference) {
  if (typeof reference !== "string" || !reference.startsWith("#/")) {
    throw new Error(`unsupported JSON Schema reference ${JSON.stringify(reference)}`);
  }
  return reference.slice(2).split("/").reduce((current, part) => current?.[part.replaceAll("~1", "/").replaceAll("~0", "~")], root);
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validate(root, schema, value, path, errors) {
  if (schema === true) return;
  if (schema === false) {
    errors.push(`${path} is not allowed`);
    return;
  }
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) {
    throw new Error(`invalid JSON Schema at ${path}`);
  }
  if (schema.$ref) {
    const target = resolveReference(root, schema.$ref);
    if (target === undefined) throw new Error(`unresolved JSON Schema reference ${schema.$ref}`);
    validate(root, target, value, path, errors);
    return;
  }
  if (schema.allOf) schema.allOf.forEach(entry => validate(root, entry, value, path, errors));
  if (schema.anyOf) {
    const variants = schema.anyOf.map(entry => {
      const nested = [];
      validate(root, entry, value, path, nested);
      return nested;
    });
    if (!variants.some(entry => entry.length === 0)) errors.push(`${path} must match at least one schema variant`);
  }
  if (schema.oneOf) {
    const matches = schema.oneOf.filter(entry => {
      const nested = [];
      validate(root, entry, value, path, nested);
      return nested.length === 0;
    });
    if (matches.length !== 1) errors.push(`${path} must match exactly one schema variant`);
  }
  if (schema.if) {
    const nested = [];
    validate(root, schema.if, value, path, nested);
    if (nested.length === 0 && schema.then) validate(root, schema.then, value, path, errors);
    if (nested.length !== 0 && schema.else) validate(root, schema.else, value, path, errors);
  }
  if (schema.type && !typeMatches(value, schema.type)) {
    errors.push(`${path} must be ${schema.type}`);
    return;
  }
  if (Object.hasOwn(schema, "const") && !sameJson(value, schema.const)) errors.push(`${path} must equal ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.some(entry => sameJson(value, entry))) errors.push(`${path} must be an allowed value`);
  if (schema.pattern && (typeof value !== "string" || !(new RegExp(schema.pattern)).test(value))) errors.push(`${path} does not match its required pattern`);
  if (schema.minLength != null && (typeof value !== "string" || value.length < schema.minLength)) errors.push(`${path} is shorter than minLength`);
  if (schema.maxLength != null && (typeof value !== "string" || value.length > schema.maxLength)) errors.push(`${path} is longer than maxLength`);
  if (schema.minimum != null && (typeof value !== "number" || value < schema.minimum)) errors.push(`${path} is below minimum`);
  if (schema.maximum != null && (typeof value !== "number" || value > schema.maximum)) errors.push(`${path} is above maximum`);
  if (Array.isArray(value)) {
    if (schema.minItems != null && value.length < schema.minItems) errors.push(`${path} has fewer than minItems`);
    if (schema.maxItems != null && value.length > schema.maxItems) errors.push(`${path} has more than maxItems`);
    if (schema.uniqueItems && new Set(value.map(entry => JSON.stringify(entry))).size !== value.length) errors.push(`${path} must have unique items`);
    const prefixItems = Array.isArray(schema.prefixItems) ? schema.prefixItems : [];
    for (const [index, entrySchema] of prefixItems.entries()) {
      if (index < value.length) validate(root, entrySchema, value[index], `${path}[${index}]`, errors);
    }
    if (Object.hasOwn(schema, "items")) {
      const start = prefixItems.length;
      for (let index = start; index < value.length; index += 1) {
        validate(root, schema.items, value[index], `${path}[${index}]`, errors);
      }
    }
  }
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const required of schema.required || []) {
      if (!Object.hasOwn(value, required)) errors.push(`${path}.${required} is required`);
    }
    const properties = schema.properties || {};
    for (const [key, entry] of Object.entries(properties)) {
      if (Object.hasOwn(value, key)) validate(root, entry, value[key], `${path}.${key}`, errors);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(properties, key)) errors.push(`${path}.${key} is not allowed`);
      }
    } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      for (const [key, entry] of Object.entries(value)) {
        if (!Object.hasOwn(properties, key)) validate(root, schema.additionalProperties, entry, `${path}.${key}`, errors);
      }
    }
  }
}

/** Return a concise list of schema violations for a root $ref or schema object. */
export function validateJsonSchema(root, value, schema) {
  const selectedSchema = arguments.length >= 3 ? schema : root;
  if (selectedSchema === undefined) {
    throw new Error("JSON Schema selection is undefined");
  }
  const errors = [];
  validate(root, selectedSchema, value, "$", errors);
  return errors;
}

export function assertJsonSchema(root, value, schema) {
  const errors = arguments.length >= 3
    ? validateJsonSchema(root, value, schema)
    : validateJsonSchema(root, value);
  if (errors.length) throw new Error(`JSON Schema validation failed:\n- ${errors.join("\n- ")}`);
  return value;
}
