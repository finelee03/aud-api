// aud-api/ble-bridge.js
const debug = (...a) => console.log('[api/ble]', ...a);

function attachBleNamespaces(io, { gatewayToken }) {
  const stream = io.of('/stream');
  stream.on('connection', (s) => {
    debug('browser connected /stream');
    s.emit('hello', { ok: true });
  });

  const gw = io.of('/gw');
  gw.use((socket, next) => {
    const token = socket.handshake?.auth?.token
      || socket.handshake?.query?.token
      || socket.handshake?.headers?.['x-gateway-token'];
    if (token !== gatewayToken) return next(new Error('unauthorized'));
    next();
  });
  gw.on('connection', (s) => {
    debug('gateway connected /gw');
    s.on('uid', (payload) => {
      if (!payload?.uid) return;
      stream.emit('uid', payload);           // 브라우저로 재방송
    });
  });
}

function startBleBridge(io, opts = {}) {
  const gatewayToken = opts.gatewayToken || process.env.GATEWAY_TOKEN || '';
  attachBleNamespaces(io, { gatewayToken });
  if (opts.log) {
    console.log('[ble] namespaces attached', gatewayToken ? '(gateway token set)' : '(gateway token missing)');
  }
}

module.exports = { attachBleNamespaces, startBleBridge };
