/**
 * PetraWebSocket — Sovereign WebSocket Server (ported to Paperclip)
 * ETWC Wave 2A — Replaces the `ws` npm package with zero external dependencies.
 *
 * Implements RFC 6455 WebSocket protocol using only:
 *   node:http, node:crypto, node:net, node:stream, node:events
 *
 * Public API is wire-compatible with `ws` (WebSocketServer + WebSocket classes).
 *
 * Architecture:
 *   PetraWebSocketServer({ noServer?, server? })
 *     → handleUpgrade(req, socket, head, callback)
 *     → emits 'connection' with (PetraWebSocket, req)
 *
 *   PetraWebSocket (per-connection)
 *     → send(data)           — server → client (unmasked per RFC 6455 §5.1)
 *     → close(code?, reason?) — graceful close handshake
 *     → ping(data?)           — send ping frame
 *     → on('message' | 'close' | 'error' | 'ping' | 'pong', handler)
 *     → readyState            — 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
 */

import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, Server as HttpServer } from 'node:http';
import type { Socket } from 'node:net';

// ─── Constants ────────────────────────────────────────────────────────────────

const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB5137BE11';

/** RFC 6455 §11.7 — opcodes */
const OP = {
  CONTINUATION: 0x0,
  TEXT:         0x1,
  BINARY:       0x2,
  CLOSE:        0x8,
  PING:         0x9,
  PONG:         0xA,
} as const;

/** readyState values */
export const READY_STATE = {
  CONNECTING: 0,
  OPEN:       1,
  CLOSING:    2,
  CLOSED:     3,
} as const;

// ─── Types ────────────────────────────────────────────────────────────────────

type ReadyState = 0 | 1 | 2 | 3;

interface ParsedFrame {
  fin:    boolean;
  opcode: number;
  masked: boolean;
  payload: Buffer;
}

interface WebSocketServerOptions {
  noServer?: boolean;
  server?:   HttpServer;
  path?:     string;
}

// ─── Frame Parser ─────────────────────────────────────────────────────────────

function parseFrames(buf: Buffer): { frames: ParsedFrame[]; remainder: Buffer } {
  const frames: ParsedFrame[] = [];
  let offset = 0;

  while (offset < buf.length) {
    if (offset + 2 > buf.length) break;

    const b0 = buf[offset]!;
    const b1 = buf[offset + 1]!;

    const fin    = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;
    let payloadLen = b1 & 0x7f;

    let headerEnd = offset + 2;

    if (payloadLen === 126) {
      if (offset + 4 > buf.length) break;
      payloadLen = buf.readUInt16BE(headerEnd);
      headerEnd += 2;
    } else if (payloadLen === 127) {
      if (offset + 10 > buf.length) break;
      const hi = buf.readUInt32BE(headerEnd);
      const lo = buf.readUInt32BE(headerEnd + 4);
      payloadLen = hi * 0x100000000 + lo;
      headerEnd += 8;
    }

    let maskingKey: Buffer | null = null;
    if (masked) {
      if (headerEnd + 4 > buf.length) break;
      maskingKey = buf.slice(headerEnd, headerEnd + 4);
      headerEnd += 4;
    }

    if (headerEnd + payloadLen > buf.length) break;

    const rawPayload = buf.slice(headerEnd, headerEnd + payloadLen);
    const payload = maskingKey ? unmask(rawPayload, maskingKey) : rawPayload;

    frames.push({ fin, opcode, masked, payload });
    offset = headerEnd + payloadLen;
  }

  return { frames, remainder: buf.slice(offset) };
}

function unmask(payload: Buffer, key: Buffer): Buffer {
  const out = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i++) {
    out[i] = payload[i]! ^ key[i % 4]!;
  }
  return out;
}

// ─── Frame Writer ─────────────────────────────────────────────────────────────

function buildFrame(opcode: number, payload: Buffer, fin = true): Buffer {
  const len = payload.length;
  let headerLen = 2;

  if (len > 65535) {
    headerLen += 8;
  } else if (len > 125) {
    headerLen += 2;
  }

  const frame = Buffer.allocUnsafe(headerLen + len);

  frame[0] = (fin ? 0x80 : 0x00) | (opcode & 0x0f);

  if (len > 65535) {
    frame[1] = 127;
    frame.writeUInt32BE(0, 2);
    frame.writeUInt32BE(len, 6);
  } else if (len > 125) {
    frame[1] = 126;
    frame.writeUInt16BE(len, 2);
  } else {
    frame[1] = len;
  }

  payload.copy(frame, headerLen);
  return frame;
}

// ─── WebSocket Handshake ──────────────────────────────────────────────────────

function performHandshake(req: IncomingMessage, socket: Socket): boolean {
  const key = req.headers['sec-websocket-key'];
  if (!key || typeof key !== 'string') {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
    socket.destroy();
    return false;
  }

  const accept = createHash('sha1')
    .update(key + WS_MAGIC)
    .digest('base64');

  const response = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '',
    '',
  ].join('\r\n');

  socket.write(response);
  return true;
}

// ─── PetraWebSocket ───────────────────────────────────────────────────────────

export class PetraWebSocket extends EventEmitter {
  static readonly CONNECTING = READY_STATE.CONNECTING;
  static readonly OPEN       = READY_STATE.OPEN;
  static readonly CLOSING    = READY_STATE.CLOSING;
  static readonly CLOSED     = READY_STATE.CLOSED;

  readyState: ReadyState = READY_STATE.OPEN;

  private _socket: Socket;
  private _buf: Buffer = Buffer.alloc(0);
  private _closeSent = false;

  constructor(socket: Socket) {
    super();
    this._socket = socket;
    this._attachSocketEvents();
  }

  send(data: string | Buffer, options?: { binary?: boolean }): void {
    if (this.readyState !== READY_STATE.OPEN) return;

    let payload: Buffer;
    let opcode: number;

    if (typeof data === 'string') {
      payload = Buffer.from(data, 'utf8');
      opcode  = OP.TEXT;
    } else {
      payload = data;
      opcode  = (options?.binary === false) ? OP.TEXT : OP.BINARY;
    }

    this._writeFrame(opcode, payload);
  }

  ping(data?: Buffer): void {
    if (this.readyState !== READY_STATE.OPEN) return;
    this._writeFrame(OP.PING, data ?? Buffer.alloc(0));
  }

  close(code = 1000, reason = ''): void {
    if (this.readyState === READY_STATE.CLOSED) return;

    if (this.readyState === READY_STATE.OPEN && !this._closeSent) {
      this.readyState = READY_STATE.CLOSING;
      this._closeSent = true;

      const reasonBuf = Buffer.from(reason, 'utf8');
      const payload   = Buffer.allocUnsafe(2 + reasonBuf.length);
      payload.writeUInt16BE(code, 0);
      reasonBuf.copy(payload, 2);

      this._writeFrame(OP.CLOSE, payload);
    }

    setTimeout(() => this._destroy(), 100);
  }

  terminate(): void {
    this._destroy();
  }

  private _writeFrame(opcode: number, payload: Buffer): void {
    try {
      const frame = buildFrame(opcode, payload);
      this._socket.write(frame);
    } catch (err) {
      this.emit('error', err instanceof Error ? err : new Error(String(err)));
    }
  }

  private _attachSocketEvents(): void {
    this._socket.on('data', (chunk: Buffer) => {
      this._buf = Buffer.concat([this._buf, chunk]);
      this._processBuffer();
    });

    this._socket.on('close', () => {
      if (this.readyState !== READY_STATE.CLOSED) {
        this.readyState = READY_STATE.CLOSED;
        this.emit('close', 1006, '');
      }
    });

    this._socket.on('error', (err: Error) => {
      this.emit('error', err);
      this._destroy();
    });
  }

  private _processBuffer(): void {
    const { frames, remainder } = parseFrames(this._buf);
    this._buf = remainder;

    for (const frame of frames) {
      this._handleFrame(frame);
    }
  }

  private _handleFrame(frame: ParsedFrame): void {
    switch (frame.opcode) {
      case OP.TEXT:
      case OP.BINARY:
        this.emit('message', frame.payload);
        break;

      case OP.PING:
        this._writeFrame(OP.PONG, frame.payload);
        this.emit('ping', frame.payload);
        break;

      case OP.PONG:
        this.emit('pong', frame.payload);
        break;

      case OP.CLOSE: {
        let code   = 1005;
        let reason = '';
        if (frame.payload.length >= 2) {
          code   = frame.payload.readUInt16BE(0);
          reason = frame.payload.slice(2).toString('utf8');
        }

        if (!this._closeSent) {
          this._writeFrame(OP.CLOSE, frame.payload);
          this._closeSent = true;
        }

        this.readyState = READY_STATE.CLOSED;
        this.emit('close', code, reason);
        setTimeout(() => this._destroy(), 50);
        break;
      }

      case OP.CONTINUATION:
        break;
    }
  }

  private _destroy(): void {
    if (!this._socket.destroyed) {
      this._socket.destroy();
    }
    this.readyState = READY_STATE.CLOSED;
  }
}

// ─── PetraWebSocketServer ─────────────────────────────────────────────────────

export class PetraWebSocketServer extends EventEmitter {
  clients: Set<PetraWebSocket> = new Set();

  private _server:    HttpServer | null = null;
  private _path:      string | null;
  private _noServer:  boolean;
  private _upgradeListener: ((req: IncomingMessage, socket: Socket, head: Buffer) => void) | null = null;

  constructor(options: WebSocketServerOptions = {}) {
    super();
    this._noServer = options.noServer ?? false;
    this._path     = options.path ?? null;

    if (options.server && !this._noServer) {
      this._server = options.server;
      this._upgradeListener = (req: IncomingMessage, socket: Socket, head: Buffer) => {
        if (this._path && req.url !== this._path) return;
        this.handleUpgrade(req, socket, head, (ws) => {
          this.emit('connection', ws, req);
        });
      };
      this._server.on('upgrade', this._upgradeListener);
    }
  }

  handleUpgrade(
    req:      IncomingMessage,
    socket:   Socket,
    _head:    Buffer,
    callback: (ws: PetraWebSocket) => void,
  ): void {
    const ok = performHandshake(req, socket);
    if (!ok) return;

    socket.setNoDelay(true);
    socket.setTimeout(0);

    const ws = new PetraWebSocket(socket);

    this.clients.add(ws);
    ws.once('close', () => this.clients.delete(ws));

    callback(ws);
  }

  close(callback?: () => void): void {
    for (const client of this.clients) {
      client.close(1001, 'Server shutting down');
    }
    this.clients.clear();

    if (this._server && this._upgradeListener) {
      this._server.removeListener('upgrade', this._upgradeListener);
      this._upgradeListener = null;
    }

    if (callback) callback();
  }
}

// ─── Re-exports (drop-in for `import { WebSocketServer, WebSocket } from 'ws'`) ──

export { PetraWebSocket as WebSocket };
export { PetraWebSocketServer as WebSocketServer };
