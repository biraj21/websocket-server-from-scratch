import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";

const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/") {
    fs.createReadStream(path.resolve("src", "index.html")).pipe(res);
    return;
  }
});

/**
 * connected sockets
 */
const connectedSockets = new Set();

/**
 * source: https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#the_websocket_handshake
 */
const CONN_UPGRADE_MAGIC_STRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

server.on("upgrade", (req, socket, head) => {
  // ========== WebSocket: handshake ========== //
  /*
  the client will start the handshake process by contacting the server & requesting
  a WebSocket connection.

  example request from client:
  ```
  GET / HTTP/1.1
  Host: localhost:3000
  Origin: http://localhost:3000
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
  Sec-WebSocket-Version: 13
  ```

  the server will receive an "upgrade" event, in which it will
  - concatenate Sec-WebSocket-Key request header & CONN_UPGRADE_MAGIC_STRING (defined above)
  - take the SHA-1 hash of the concatenation result
  - encode it to base64 & include it in the response header like this
    ```
    HTTP/1.1 101 Switching Protocols
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    ```
  */
  const secWebSocketKey = req.headers["sec-websocket-key"];
  if (!secWebSocketKey) {
    socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
    socket.destroy();
    return;
  }

  // read https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#the_websocket_handshake
  // for WebSocket handshake
  const secWebSocketAccept = crypto
    .createHash("sha1")
    .update(secWebSocketKey + CONN_UPGRADE_MAGIC_STRING)
    .digest("base64");

  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: WebSocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${secWebSocketAccept}\r\n` +
      "\r\n",
  );

  // add this socket to our set
  connectedSockets.add(socket);

  socket.on("end", () => {
    console.log("connection ended");
    connectedSockets.delete(socket);
  });

  socket.on("error", (error) => {
    console.error("socket error:", error);
    connectedSockets.delete(socket); // Remove the socket on error
  });

  // ========== WebSocket: reading data frames  ========== //

  // https://nodejs.org/api/stream.html#event-readable
  socket.on("readable", () => {
    processDataFrame(socket);
  });
});

const PORT = 3000;
server.listen(PORT, () => console.log(`server running on port ${PORT}`));

// error handling to prevent the server from crashing
["uncaughtException", "unhandledRejection"].forEach((event) =>
  process.on(event, (err) => {
    console.error(`an unhandled error(${event}):`, err.stack || err);
  }),
);

// ========== WebSocket: porcessing data frames  ========== //
// https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#exchanging_data_frames

// bitmasks
const BM_FIN = 0b1000_0000;
const BM_OPCODE = 0b0000_1111;
const BM_MASKED = 0b1000_0000;
const BM_EXP_LEN = 0b0111_1111; // for expected payload length

// opcodes
const OP_CONT = 0x1;
const OP_TEXT = 0x1;
const OP_BIN = 0x2;

// expected payload length
const LEN_7_BITS = 125;
const LEN_16_BITS = 126;
const LEN_64_BITS = 127;

/**
 * reads data from the given socket (duplex stream).
 *
 * @param {import('stream').Duplex} socket - the socket (duplex stream) to read data from
 */
function processDataFrame(socket) {
  // 1st byte
  const [finAndOpcode] = socket.read(1);
  const fin = finAndOpcode & BM_FIN;
  const opcode = finAndOpcode & BM_OPCODE;

  // 2nd byte
  const [maskAndPayloadLen] = socket.read(1);
  const isMasked = maskAndPayloadLen & BM_MASKED;

  // it's written in MDN: Messages from the client must be masked, so your server
  // must expect this to be 1. (In fact, section 5.1 of the spec says that your
  // server must disconnect from a client if that client sends an unmasked message.)
  if (!isMasked) {
    socket.destroy();
    return;
  }

  const expectedPayloadLen = maskAndPayloadLen & BM_EXP_LEN; // 7 bits

  // decoding payload length
  let payloadLen = 0;
  if (expectedPayloadLen <= LEN_7_BITS) {
    // <= 125 - done! this is the payload length
    payloadLen = expectedPayloadLen;
  } else if (expectedPayloadLen === LEN_16_BITS) {
    // == 126 - read the next 16 bits (2 bytes) to get the payload length
    const buffer = socket.read(2);
    payloadLen = buffer.readUInt16BE();
  } else if (expectedPayloadLen === LEN_64_BITS) {
    // == 127 - read the next 64 bits (8 bytes) to get the payload length
    const buffer = socket.read(8);
    payloadLen = buffer.readBigUint64BE();
  } else {
    throw new Erorr(
      `error: readDataFrame() -> expectedPayloadLen is ${expectedPayloadLen}... how??`,
    );
  }

  // read the mask
  const mask = socket.read(4);

  // read the payload (it will be masked)
  const maskedPayload = socket.read(payloadLen);

  // unmask the payload & convert it to string
  let payload = maskedPayload.map((e, i) => e ^ mask[i % 4]);

  if (opcode === OP_TEXT) {
    const text = new TextDecoder().decode(payload);
    console.log("_DEBUG_ text:", text);
  }

  // if (connectedSockets.size <= 1) {
  //   return;
  // }

  // create WebSocket frame to broadcast message to connected sockets
  const resFrame = createResponseFrame(payload);

  // broadcast message to all sockets except this one
  for (const s of connectedSockets) {
    if (s === socket) {
      continue;
    }

    s.write(resFrame);
  }
}

/**
 * @param payload {Buffer} the payload to create frame with
 */
function createResponseFrame(payload) {
  let payloadLenBytes = 0;
  let payloadLenBuffer;

  if (payload.length <= 125) {
    payloadLenBytes = 1;
    payloadLenBuffer = Buffer.alloc(1);
    payloadLenBuffer.writeUInt8(payload.length);
  } else if (payload.length <= 2 ** 16 - 1) {
    payloadLenBytes = 2;
    payloadLenBuffer = Buffer.alloc(2);
    payloadLenBuffer.writeUint16BE(payload.length);
  } else if (payload.length <= 2 ** 64 - 1) {
    payloadLenBytes = 8;
    payloadLenBuffer = Buffer.alloc(8);
    payloadLenBuffer.writeBigUInt64BE(payload.length);
  } else {
    throw new Erorr(
      `error: createResponseFrame() -> payload.length is ${payload.length}... how??`,
    );
  }

  const frame = Buffer.alloc(1 + payloadLenBytes + payload.length);
  frame[0] = 0x81; // FIN and opcode for text frame
  payloadLenBuffer.copy(frame, 1);
  payload.copy(frame, 1 + payloadLenBytes);

  return frame;
}
