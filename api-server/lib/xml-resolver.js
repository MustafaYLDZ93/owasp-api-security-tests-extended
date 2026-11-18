'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Minimal, intentionally small XML DTD entity resolver.
 *
 * This is NOT a general-purpose XML parser — it exists solely to give the
 * test suite a REAL, controllable sink for two CWEs that a modern,
 * secure-by-default XML library (libxml2, fast-xml-parser, ...) would not
 * let us demonstrate at all:
 *
 *   - CWE-611 (XXE): resolving a `<!ENTITY x SYSTEM "file://...">` reads a
 *     local file and splices its content into the document.
 *   - CWE-776 (Entity Expansion / "Billion Laughs"): entities that reference
 *     other entities are expanded recursively; without limits the output
 *     size grows exponentially with the nesting depth.
 *
 * Both behaviours are gated by options so the SAME function backs both the
 * secure and the vulnerable server — only the options differ:
 *
 *   resolveXmlEntities(xml, { allowExternalEntities: false, maxExpandedLength: 100_000, maxEntityDepth: 8 })  // secure
 *   resolveXmlEntities(xml, { allowExternalEntities: true,  maxExpandedLength: 50_000_000, maxEntityDepth: 30 }) // vulnerable
 */

const DOCTYPE_RE = /<!DOCTYPE\s+[^\[>]*(?:\[([\s\S]*?)\]\s*)?>/i;
const ENTITY_DEF_RE = /<!ENTITY\s+(\w+)\s+(?:SYSTEM\s+["']([^"']+)["']|["']([^"']*)["'])\s*>/gi;
// NOTE: a fresh RegExp instance is created per call site below instead of a
// shared module-level `g`-flag constant — expand() recurses, and a shared
// stateful regex's lastIndex would otherwise be corrupted across the
// recursive calls operating on different `text` arguments.

class XmlPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code; // 'EXTERNAL_ENTITIES_DISABLED' | 'ENTITY_EXPANSION_LIMIT' | 'ENTITY_DEPTH_LIMIT'
  }
}

function readSystemEntity(uri, baseDir) {
  if (!uri.startsWith('file://')) {
    // Only local-file SYSTEM entities are implemented; http(s) SSRF-via-XXE
    // is intentionally out of scope here (covered by the dedicated SSRF
    // family against /api/webhooks, to avoid duplicate network side effects
    // in the test run — see DESIGN.md §3).
    throw new XmlPolicyError('UNSUPPORTED_SCHEME', `Unsupported SYSTEM entity scheme: ${uri}`);
  }
  const rawPath = uri.slice('file://'.length);
  const resolved = path.isAbsolute(rawPath) ? rawPath : path.join(baseDir, rawPath);
  return fs.readFileSync(resolved, 'utf8');
}

function parseEntityDefinitions(doctypeSubset, { allowExternalEntities, baseDir }) {
  const entities = new Map();
  if (!doctypeSubset) return entities;
  let match;
  ENTITY_DEF_RE.lastIndex = 0;
  while ((match = ENTITY_DEF_RE.exec(doctypeSubset)) !== null) {
    const [, name, systemUri, literalValue] = match;
    if (systemUri !== undefined) {
      if (!allowExternalEntities) {
        entities.set(name, { error: new XmlPolicyError('EXTERNAL_ENTITIES_DISABLED', `SYSTEM entity "&${name};" rejected: external entities are disabled`) });
      } else {
        entities.set(name, { value: readSystemEntity(systemUri, baseDir) });
      }
    } else {
      entities.set(name, { value: literalValue ?? '' });
    }
  }
  return entities;
}

/**
 * Recursively expands &name; references, honouring depth/length limits.
 * Throws XmlPolicyError when a limit would be exceeded (this is the oracle
 * the secure server uses to return 400/413; the vulnerable server simply
 * has much higher limits so realistic test payloads succeed instead).
 */
function expand(text, entities, depthRemaining, maxExpandedLength, lengthState) {
  if (depthRemaining < 0) {
    throw new XmlPolicyError('ENTITY_DEPTH_LIMIT', 'Entity reference nesting exceeds the allowed depth');
  }
  let result = '';
  let lastIndex = 0;
  const refRe = /&(\w+);/g;
  let match;
  while ((match = refRe.exec(text)) !== null) {
    result += text.slice(lastIndex, match.index);
    lastIndex = refRe.lastIndex;
    const [, name] = match;
    const def = entities.get(name);
    if (!def) {
      result += match[0]; // Unknown entity — leave as-is
      continue;
    }
    if (def.error) throw def.error;
    const expandedChild = expand(def.value, entities, depthRemaining - 1, maxExpandedLength, lengthState);
    result += expandedChild;
    lengthState.total += expandedChild.length;
    if (lengthState.total > maxExpandedLength) {
      throw new XmlPolicyError('ENTITY_EXPANSION_LIMIT', `Expanded entity content exceeds ${maxExpandedLength} bytes`);
    }
  }
  result += text.slice(lastIndex);
  return result;
}

/**
 * Parses `xmlSource`, resolves all entities under the given policy, and
 * returns the fully expanded document string.
 *
 * @param {string} xmlSource
 * @param {{allowExternalEntities:boolean, maxExpandedLength:number, maxEntityDepth:number, baseDir:string}} opts
 */
function resolveXmlEntities(xmlSource, opts) {
  const { allowExternalEntities, maxExpandedLength, maxEntityDepth, baseDir } = opts;
  const doctypeMatch = DOCTYPE_RE.exec(xmlSource);
  const entities = parseEntityDefinitions(doctypeMatch?.[1], { allowExternalEntities, baseDir });
  const body = doctypeMatch ? xmlSource.slice(doctypeMatch.index + doctypeMatch[0].length) : xmlSource;
  const lengthState = { total: body.length };
  if (lengthState.total > maxExpandedLength) {
    throw new XmlPolicyError('ENTITY_EXPANSION_LIMIT', `Document exceeds ${maxExpandedLength} bytes before expansion`);
  }
  return expand(body, entities, maxEntityDepth, maxExpandedLength, lengthState);
}

/** Extracts the inner text of the first `<tagName>...</tagName>` occurrence. */
function extractTag(xml, tagName) {
  const re = new RegExp(`<${tagName}>([\\s\\S]*?)<\\/${tagName}>`, 'i');
  const m = re.exec(xml);
  return m ? m[1] : null;
}

module.exports = { resolveXmlEntities, extractTag, XmlPolicyError };
