import { connect } from "cloudflare:sockets"
const WebSocketPair = globalThis.WebSocketPair // WebSocketPair is a global in Cloudflare Workers, not imported

const UUID = "aaaaaabb-4ddd-4eee-9fff-ffffffffffff"
const enc = (s) => new TextEncoder().encode(s)
const dec = (a) => new TextDecoder().decode(a)
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("")
const concat = (...a) => {
  const r = new Uint8Array(a.reduce((s, x) => s + x.length, 0))
  let o = 0
  for (const x of a) {
    r.set(x, o)
    o += x.length
  }
  return r
}
const alloc = (n, f = 0) => {
  const a = new Uint8Array(n)
  if (f) a.fill(f)
  return a
}

// KDF Salt Constants
const KDF = {
  LEN_KEY: enc("VMess Header AEAD Key_Length"),
  LEN_IV: enc("VMess Header AEAD Nonce_Length"),
  PAYLOAD_KEY: enc("VMess Header AEAD Key"),
  PAYLOAD_IV: enc("VMess Header AEAD Nonce"),
  RESP_LEN_KEY: enc("AEAD Resp Header Len Key"),
  RESP_LEN_IV: enc("AEAD Resp Header Len IV"),
  RESP_KEY: enc("AEAD Resp Header Key"),
  RESP_IV: enc("AEAD Resp Header IV"),
}

// SHA256 Implementation
function sha256(msg) {
  const m = msg instanceof Uint8Array ? msg : enc(msg)
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
  ])
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ])
  const rotr = (x, n) => (x >>> n) | (x << (32 - n))
  const pad = new Uint8Array(m.length + 1 + ((56 - ((m.length + 1) % 64) + 64) % 64) + 8)
  pad.set(m)
  pad[m.length] = 0x80
  new DataView(pad.buffer).setUint32(pad.length - 4, m.length * 8, false)
  const W = new Uint32Array(64)
  for (let i = 0; i < pad.length; i += 64) {
    const blk = new DataView(pad.buffer, i, 64)
    for (let t = 0; t < 16; t++) W[t] = blk.getUint32(t * 4, false)
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, h] = H
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const T1 = (h + S1 + ((e & f) ^ (~e & g)) + K[t] + W[t]) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const T2 = (S0 + ((a & b) ^ (a & c) ^ (b & c))) >>> 0
      h = g
      g = f
      f = e
      e = (d + T1) >>> 0
      d = c
      c = b
      b = a
      a = (T1 + T2) >>> 0
    }
    H[0] = (H[0] + a) >>> 0
    H[1] = (H[1] + b) >>> 0
    H[2] = (H[2] + c) >>> 0
    H[3] = (H[3] + d) >>> 0
    H[4] = (H[4] + e) >>> 0
    H[5] = (H[5] + f) >>> 0
    H[6] = (H[6] + g) >>> 0
    H[7] = (H[7] + h) >>> 0
  }
  const r = new Uint8Array(32),
    rv = new DataView(r.buffer)
  for (let i = 0; i < 8; i++) rv.setUint32(i * 4, H[i], false)
  return r
}

// MD5 Implementation
function md5(data, salt) {
  let m = data instanceof Uint8Array ? data : enc(data)
  if (salt) m = concat(m, salt instanceof Uint8Array ? salt : enc(salt))
  const K = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
    0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
    0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
    0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391,
  ])
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15,
    21,
  ]
  let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  const pad = new Uint8Array(m.length + 1 + ((56 - ((m.length + 1) % 64) + 64) % 64) + 8)
  pad.set(m)
  pad[m.length] = 0x80
  const v = new DataView(pad.buffer)
  v.setUint32(pad.length - 8, (m.length * 8) >>> 0, true)
  v.setUint32(pad.length - 4, ((m.length * 8) / 0x100000000) >>> 0, true)
  const rotl = (x, n) => (x << n) | (x >>> (32 - n))
  for (let i = 0; i < pad.length; i += 64) {
    const M = new Uint32Array(16)
    for (let j = 0; j < 16; j++) M[j] = v.getUint32(i + j * 4, true)
    let [A, B, C, D] = [a0, b0, c0, d0]
    for (let j = 0; j < 64; j++) {
      let F, g
      if (j < 16) {
        F = (B & C) | (~B & D)
        g = j
      } else if (j < 32) {
        F = (D & B) | (~D & C)
        g = (5 * j + 1) % 16
      } else if (j < 48) {
        F = B ^ C ^ D
        g = (3 * j + 5) % 16
      } else {
        F = C ^ (B | ~D)
        g = (7 * j) % 16
      }
      F = (F + A + K[j] + M[g]) >>> 0
      A = D
      D = C
      C = B
      B = (B + rotl(F, S[j])) >>> 0
    }
    a0 = (a0 + A) >>> 0
    b0 = (b0 + B) >>> 0
    c0 = (c0 + C) >>> 0
    d0 = (d0 + D) >>> 0
  }
  const r = new Uint8Array(16),
    rv = new DataView(r.buffer)
  rv.setUint32(0, a0, true)
  rv.setUint32(4, b0, true)
  rv.setUint32(8, c0, true)
  rv.setUint32(12, d0, true)
  return r
}

// HMAC & KDF
const hmac = (key, hashFn) => {
  const ipad = alloc(64, 0x36),
    opad = alloc(64, 0x5c)
  const k = key instanceof Uint8Array ? key : enc(key)
  for (let i = 0; i < k.length; i++) {
    ipad[i] ^= k[i]
    opad[i] ^= k[i]
  }
  return (data) => hashFn(concat(opad, hashFn(concat(ipad, data))))
}
const kdf = (key, path) => {
  let fn = sha256
  fn = hmac(enc("VMess AEAD KDF"), fn)
  for (const p of path) fn = hmac(p, fn)
  return fn(key)
}

// AES-GCM
const aesGcm = async (key, iv, data, aad, mode) => {
  const k = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, [mode])
  const r = await crypto.subtle[mode](
    { name: "AES-GCM", iv, additionalData: aad || new Uint8Array(0), tagLength: 128 },
    k,
    data,
  )
  return new Uint8Array(r)
}
const aesDecrypt = (k, iv, d, aad) => aesGcm(k, iv, d, aad, "decrypt")
const aesEncrypt = (k, iv, d, aad) => aesGcm(k, iv, d, aad, "encrypt")

// UUID to Buffer
const uuidToBuffer = (uuid) => {
  const h = uuid.replace(/-/g, ""),
    a = new Uint8Array(16)
  for (let i = 0; i < 16; i++) a[i] = Number.parseInt(h.substr(i * 2, 2), 16)
  return a
}

// Parse Address Helper (unified for all protocols)
const parseAddress = (buf, idx, type) => {
  let len = 0,
    addr = "",
    i = idx
  if (type === 1) {
    // IPv4
    len = 4
    addr = new Uint8Array(buf.slice(i, i + len)).join(".")
  } else if (type === 2 || type === 3) {
    // Domain
    len = buf[i]
    i++
    addr = dec(buf.slice(i, i + len))
  } else if (type === 3 && len === 0) {
    // IPv6 fallback
    len = 16
    const dv = new DataView(buf.slice(i, i + len).buffer)
    addr = Array.from({ length: 8 }, (_, j) => dv.getUint16(j * 2).toString(16)).join(":")
  }
  // Handle IPv6 specifically when type indicates it
  if (type === 3 && addr === "") {
    len = 16
    const dv = new DataView(buf.slice(i, i + len).buffer)
    addr = Array.from({ length: 8 }, (_, j) => dv.getUint16(j * 2).toString(16)).join(":")
  }
  return { addr, end: i + len }
}

// Unified address parser
const getAddress = (buf, idx, addrType, domainType = 2) => {
  let len = 0,
    addr = "",
    i = idx
  switch (addrType) {
    case 1: // IPv4
      addr = new Uint8Array(buf.slice(i, i + 4)).join(".")
      i += 4
      break
    case domainType: // Domain
      len = buf[i]
      i++
      addr = dec(buf.slice(i, i + len))
      i += len
      break
    case 3: // IPv6
      const dv = new DataView(buf.slice(i, i + 16).buffer)
      addr = Array.from({ length: 8 }, (_, j) => dv.getUint16(j * 2).toString(16)).join(":")
      i += 16
      break
  }
  return { addr, idx: i }
}

// Base64 Decode
const b64decode = (s) => {
  if (!s) return { error: null }
  try {
    const d = atob(s.replace(/-/g, "+").replace(/_/g, "/"))
    return { data: Uint8Array.from(d, (c) => c.charCodeAt(0)).buffer, error: null }
  } catch (e) {
    return { error: e }
  }
}

// Protocol Detection
async function detectProtocol(buf) {
  if (await isVMess(buf)) return "vmess"
  if (buf.length >= 62) {
    const d = buf.slice(56, 60)
    if (d[0] === 0x0d && d[1] === 0x0a && [1, 3, 127].includes(d[2]) && [1, 3, 4, 127].includes(d[3])) return "trojan"
  }
  const uuid = hex(buf.slice(1, 17).buffer)
  if (/^\w{8}\w{4}4\w{3}[89ab]\w{3}\w{12}$/.test(uuid)) return "vless"
  return "ss"
}

async function isVMess(buf) {
  if (buf.length < 42) return false
  try {
    const uuidBytes = uuidToBuffer(UUID)
    const authId = buf.subarray(0, 16),
      lenEnc = buf.subarray(16, 34),
      nonce = buf.subarray(34, 42)
    const key = md5(uuidBytes, enc("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
    const lenKey = kdf(key, [KDF.LEN_KEY, authId, nonce]).subarray(0, 16)
    const lenIv = kdf(key, [KDF.LEN_IV, authId, nonce]).subarray(0, 12)
    const dec = await aesDecrypt(lenKey, lenIv, lenEnc, authId)
    const len = (dec[0] << 8) | dec[1]
    return len > 0 && len < 4096
  } catch {
    return false
  }
}

// Protocol Parsers
async function parseVMess(buf) {
  const uuidBytes = uuidToBuffer(UUID)
  const authId = buf.subarray(0, 16),
    lenEnc = buf.subarray(16, 34),
    nonce = buf.subarray(34, 42)
  const rem = buf.subarray(42)

  const key = md5(uuidBytes, enc("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
  const lenKey = kdf(key, [KDF.LEN_KEY, authId, nonce]).subarray(0, 16)
  const lenIv = kdf(key, [KDF.LEN_IV, authId, nonce]).subarray(0, 12)
  const decLen = await aesDecrypt(lenKey, lenIv, lenEnc, authId)
  const hdrLen = (decLen[0] << 8) | decLen[1]

  const cmdEnc = rem.subarray(0, hdrLen + 16)
  const rawData = rem.subarray(hdrLen + 16)

  const payloadKey = kdf(key, [KDF.PAYLOAD_KEY, authId, nonce]).subarray(0, 16)
  const payloadIv = kdf(key, [KDF.PAYLOAD_IV, authId, nonce]).subarray(0, 12)
  const cmd = await aesDecrypt(payloadKey, payloadIv, cmdEnc, authId)

  if (cmd[0] !== 1) throw new Error("Invalid VMess version")

  const iv = cmd.subarray(1, 17),
    keyResp = cmd.subarray(17, 33)
  const respAuth = cmd[33],
    command = cmd[37]
  const port = (cmd[38] << 8) | cmd[39],
    addrType = cmd[40]

  let addr = "",
    i = 41
  if (addrType === 1) {
    addr = `${cmd[i]}.${cmd[i + 1]}.${cmd[i + 2]}.${cmd[i + 3]}`
    i += 4
  } else if (addrType === 2) {
    const len = cmd[i]
    i++
    addr = dec(cmd.subarray(i, i + len))
    i += len
  } else if (addrType === 3) {
    addr = Array.from({ length: 8 }, (_, j) => ((cmd[i + j * 2] << 8) | cmd[i + j * 2 + 1]).toString(16)).join(":")
    i += 16
  }

  const respKeyBase = sha256(keyResp).subarray(0, 16),
    respIvBase = sha256(iv).subarray(0, 16)
  const encLen = await aesEncrypt(
    kdf(respKeyBase, [KDF.RESP_LEN_KEY]).subarray(0, 16),
    kdf(respIvBase, [KDF.RESP_LEN_IV]).subarray(0, 12),
    new Uint8Array([0, 4]),
  )
  const encPayload = await aesEncrypt(
    kdf(respKeyBase, [KDF.RESP_KEY]).subarray(0, 16),
    kdf(respIvBase, [KDF.RESP_IV]).subarray(0, 12),
    new Uint8Array([respAuth, 0, 0, 0]),
  )

  return { addr, port, data: rawData, ver: concat(encLen, encPayload), udp: command === 2 }
}

function parseTrojan(buf) {
  const data = buf.slice(58)
  if (data.length < 6) return { err: "Invalid Trojan data" }

  const cmd = data[0],
    addrType = data[1]
  let i = 2,
    addr = ""

  if (addrType === 1) {
    addr = new Uint8Array(data.slice(i, i + 4)).join(".")
    i += 4
  } else if (addrType === 3) {
    const len = data[i]
    i++
    addr = dec(data.slice(i, i + len))
    i += len
  } else if (addrType === 4) {
    const dv = new DataView(data.slice(i, i + 16).buffer)
    addr = Array.from({ length: 8 }, (_, j) => dv.getUint16(j * 2).toString(16)).join(":")
    i += 16
  } else return { err: `Invalid Trojan address type: ${addrType}` }

  const port = new DataView(data.buffer, data.byteOffset + i, 2).getUint16(0)
  return { addr, port, data: data.slice(i + 4), ver: null, udp: cmd === 3 }
}

function parseVLESS(buf) {
  const ver = buf[0],
    optLen = buf[17],
    cmd = buf[18 + optLen]
  if (cmd !== 1 && cmd !== 2) return { err: `Unsupported VLESS command: ${cmd}` }

  const portIdx = 19 + optLen
  const port = new DataView(buf.buffer, buf.byteOffset + portIdx, 2).getUint16(0)
  const addrType = buf[portIdx + 2]
  let i = portIdx + 3,
    addr = ""

  if (addrType === 1) {
    addr = new Uint8Array(buf.slice(i, i + 4)).join(".")
    i += 4
  } else if (addrType === 2) {
    const len = buf[i]
    i++
    addr = dec(buf.slice(i, i + len))
    i += len
  } else if (addrType === 3) {
    const dv = new DataView(buf.slice(i, i + 16).buffer)
    addr = Array.from({ length: 8 }, (_, j) => dv.getUint16(j * 2).toString(16)).join(":")
    i += 16
  } else return { err: `Invalid VLESS address type: ${addrType}` }

  return { addr, port, data: buf.slice(i), ver: new Uint8Array([ver, 0]), udp: cmd === 2 }
}

function parseSS(buf) {
  const addrType = buf[0]
  let i = 1,
    addr = ""

  console.log("[v0] SS addrType:", addrType, "bufLen:", buf.length)

  if (addrType === 1) {
    // IPv4
    addr = new Uint8Array(buf.slice(i, i + 4)).join(".")
    i += 4
  } else if (addrType === 3) {
    // Domain - first byte is length
    const len = buf[i]
    i++
    addr = dec(buf.slice(i, i + len))
    i += len
  } else if (addrType === 4) {
    // IPv6
    const dv = new DataView(buf.slice(i, i + 16).buffer)
    addr = Array.from({ length: 8 }, (_, j) => dv.getUint16(j * 2).toString(16)).join(":")
    i += 16
  } else {
    return { err: `Invalid SS address type: ${addrType}` }
  }

  console.log("[v0] SS parsed addr:", addr, "index:", i)

  if (!addr) return { err: "SS address empty" }

  const portBuf = buf.slice(i, i + 2)
  if (portBuf.length < 2) return { err: "SS port data too short" }

  const port = new DataView(portBuf.buffer, portBuf.byteOffset, 2).getUint16(0)

  console.log("[v0] SS port:", port)

  return { addr, port, data: buf.slice(i + 2), ver: null, udp: port === 53 }
}

// WebSocket Stream
function createWSStream(ws, earlyData, log) {
  let cancelled = false
  return new ReadableStream({
    start(ctrl) {
      ws.addEventListener("message", (e) => !cancelled && ctrl.enqueue(e.data))
      ws.addEventListener("close", () => {
        safeClose(ws)
        !cancelled && ctrl.close()
      })
      ws.addEventListener("error", (e) => {
        log("WS error")
        ctrl.error(e)
      })
      const { data, error } = b64decode(earlyData)
      if (error) ctrl.error(error)
      else if (data) ctrl.enqueue(data)
    },
    cancel(r) {
      if (!cancelled) {
        log(`Stream cancelled: ${r}`)
        cancelled = true
        safeClose(ws)
      }
    },
  })
}

// TCP Handler
async function handleTCP(socket, addr, port, data, ws, respHdr, log) {
  const doConnect = async (a, p) => {
    const tcp = connect({ hostname: a, port: p })
    socket.value = tcp
    log(`Connected to ${a}:${p}`)
    const w = tcp.writable.getWriter()
    await w.write(data)
    w.releaseLock()
    return tcp
  }

  const retry = async () => {
    const px = globalThis.pxip
    const tcp = await doConnect(px?.split(/[:=-]/)[0] || addr, px?.split(/[:=-]/)[1] || port)
    tcp.closed.catch((e) => console.log("Retry error", e)).finally(() => safeClose(ws))
    pipeToWS(tcp, ws, respHdr, null, log)
  }

  const tcp = await doConnect(addr, port)
  pipeToWS(tcp, ws, respHdr, retry, log)
}

// Pipe remote to WebSocket
async function pipeToWS(remote, ws, hdr, retry, log) {
  let header = hdr,
    hasData = false
  await remote.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, ctrl) {
          hasData = true
          if (ws.readyState !== 1) ctrl.error("WS closed")
          ws.send(header ? await new Blob([header, chunk]).arrayBuffer() : chunk)
          header = null
        },
        close() {
          log(`Remote closed, hasData: ${hasData}`)
        },
        abort(r) {
          console.error("Remote abort", r)
        },
      }),
    )
    .catch((e) => {
      console.error("Pipe error", e)
      safeClose(ws)
    })
  if (!hasData && retry) {
    log("Retrying...")
    retry()
  }
}

// UDP Handler (DNS only)
async function handleUDP(ws, respHdr, log) {
  let hdrSent = false
  const ts = new TransformStream({
    transform(chunk, ctrl) {
      for (let i = 0; i < chunk.byteLength; ) {
        const len = new DataView(chunk.buffer, chunk.byteOffset + i, 2).getUint16(0)
        ctrl.enqueue(new Uint8Array(chunk.slice(i + 2, i + 2 + len)))
        i += 2 + len
      }
    },
  })

  ts.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch("https://1.1.1.1/dns-query", {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: chunk,
          })
          const dns = await resp.arrayBuffer()
          const size = new Uint8Array([(dns.byteLength >> 8) & 0xff, dns.byteLength & 0xff])
          if (ws.readyState === 1) {
            log(`DoH success, len: ${dns.byteLength}`)
            ws.send(await new Blob(hdrSent ? [size, dns] : [respHdr, size, dns]).arrayBuffer())
            hdrSent = true
          }
        },
      }),
    )
    .catch((e) => log("DNS error: " + e))

  const w = ts.writable.getWriter()
  return { write: (chunk) => w.write(chunk) }
}

const safeClose = (ws) => {
  try {
    if (ws.readyState === 1 || ws.readyState === 2) ws.close()
  } catch {}
}

// Main Handler
export default {
  async fetch(req, env, ctx) {
    try {
      const url = new URL(req.url)
      if (req.headers.get("Upgrade") === "websocket") {
        const px = url.pathname.match(/^\/(.+[:=-]\d+)$/)
        if (px) globalThis.pxip = px[1]
        return await handleWS(req)
      }
      return new Response("Not Found", { status: 404 })
    } catch (e) {
      return new Response(`Error: ${e}`, { status: 500 })
    }
  },
}

async function handleWS(req) {
  const [client, ws] = Object.values(new WebSocketPair())
  ws.accept()

  let addrLog = "",
    portLog = ""
  const log = (msg, e) => console.log(`[${addrLog}:${portLog}] ${msg}`, e || "")

  const earlyData = req.headers.get("sec-websocket-protocol") || ""
  const stream = createWSStream(ws, earlyData, log)
  const socket = { value: null }
  let udpWrite = null,
    isDNS = false

  stream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (isDNS && udpWrite) return udpWrite(chunk)
          if (socket.value) {
            const w = socket.value.writable.getWriter()
            await w.write(chunk)
            w.releaseLock()
            return
          }

          const buf = new Uint8Array(chunk)
          const proto = await detectProtocol(buf)
          let hdr

          if (proto === "vmess") hdr = await parseVMess(buf)
          else if (proto === "trojan") hdr = parseTrojan(buf)
          else if (proto === "vless") hdr = parseVLESS(buf)
          else hdr = parseSS(buf)

          if (hdr.err) throw new Error(hdr.err)

          addrLog = hdr.addr
          portLog = `${hdr.port} -> ${hdr.udp ? "UDP" : "TCP"}`

          if (hdr.udp) {
            if (hdr.port === 53) isDNS = true
            else throw new Error("UDP only for DNS port 53")
          }

          if (isDNS) {
            const { write } = await handleUDP(ws, hdr.ver, log)
            udpWrite = write
            udpWrite(hdr.data)
            return
          }

          handleTCP(socket, hdr.addr, hdr.port, hdr.data, ws, hdr.ver, log)
        },
        close() {
          log("Stream closed")
        },
        abort(r) {
          log("Stream aborted", JSON.stringify(r))
        },
      }),
    )
    .catch((e) => log("Pipe error", e))

  return new Response(null, { status: 101, webSocket: client })
}
