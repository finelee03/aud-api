function assertItemId(id) {
  if (!/^[A-Za-z0-9_\-:.]{3,128}$/.test(String(id || '')))
    throw new Error('invalid-item-id');
}

function assertNS(ns) {
  if (!/^[a-z0-9_\-]{1,64}$/.test(String(ns || '')))
    throw new Error('invalid-ns');
}

function assertLabel(label) {
  if (!/^.{1,120}$/.test(String(label || '')))
    throw new Error('invalid-label');
}

module.exports = { assertItemId, assertNS, assertLabel };
