/* 小さな ZIP 書き出し(圧縮なし。写真・動画はもともと圧縮済みなので、そのまま入れる)
   - 1ファイルずつ書いていくので、全部をメモリに置かなくていい
   - 4GB を超える ZIP(ZIP64)や、65535 件を超える場合にも対応 */
const TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
export function crc32(u8) { let c = 0xFFFFFFFF; for (let i = 0; i < u8.length; i++) c = TABLE[(c ^ u8[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
const enc = new TextEncoder();
function dosTime(ms) {
  const d = new Date(ms > 315532800000 ? ms : 315532800000);
  return [((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xFFFF, (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xFFFF];
}
export class ZipWriter {
  constructor(sink, opt) { this.sink = sink; this.off = 0; this.entries = []; this.force64 = !!(opt && opt.zip64); }
  async _w(u8) { await this.sink.write(u8); this.off += u8.length; }
  async add(name, data, mtime) {
    if (data.length >= 0xFFFFFFFF) throw new Error('1ファイルが4GBを超えています');
    const nb = enc.encode(name), [tm, dt] = dosTime(mtime), crc = crc32(data), start = this.off;
    const h = new DataView(new ArrayBuffer(30));
    h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, 0, true);
    h.setUint16(10, tm, true); h.setUint16(12, dt, true); h.setUint32(14, crc, true); h.setUint32(18, data.length, true); h.setUint32(22, data.length, true);
    h.setUint16(26, nb.length, true); h.setUint16(28, 0, true);
    await this._w(new Uint8Array(h.buffer)); await this._w(nb); await this._w(data);
    this.entries.push({ nb, tm, dt, crc, size: data.length, start });
  }
  async finish() {
    const cdStart = this.off;
    for (const e of this.entries) {
      const big = e.start >= 0xFFFFFFFF || this.force64, extra = big ? 12 : 0;
      const c = new DataView(new ArrayBuffer(46 + extra));
      c.setUint32(0, 0x02014b50, true); c.setUint16(4, big ? 45 : 20, true); c.setUint16(6, big ? 45 : 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true);
      c.setUint16(12, e.tm, true); c.setUint16(14, e.dt, true); c.setUint32(16, e.crc, true); c.setUint32(20, e.size, true); c.setUint32(24, e.size, true);
      c.setUint16(28, e.nb.length, true); c.setUint16(30, extra, true); c.setUint16(32, 0, true); c.setUint16(34, 0, true); c.setUint16(36, 0, true); c.setUint32(38, 0, true);
      c.setUint32(42, big ? 0xFFFFFFFF : e.start, true);
      if (big) { c.setUint16(46, 0x0001, true); c.setUint16(48, 8, true); c.setBigUint64(50, BigInt(e.start), true); }
      const buf = new Uint8Array(c.buffer); await this._w(buf.subarray(0, 46)); await this._w(e.nb); if (big) await this._w(buf.subarray(46));
    }
    const cdSize = this.off - cdStart, n = this.entries.length;
    const need64 = this.force64 || n >= 0xFFFF || cdStart >= 0xFFFFFFFF || cdSize >= 0xFFFFFFFF;
    if (need64) {
      const e64 = this.off, r = new DataView(new ArrayBuffer(56 + 20));
      r.setUint32(0, 0x06064b50, true); r.setBigUint64(4, 44n, true); r.setUint16(12, 45, true); r.setUint16(14, 45, true); r.setUint32(16, 0, true); r.setUint32(20, 0, true);
      r.setBigUint64(24, BigInt(n), true); r.setBigUint64(32, BigInt(n), true); r.setBigUint64(40, BigInt(cdSize), true); r.setBigUint64(48, BigInt(cdStart), true);
      r.setUint32(56, 0x07064b50, true); r.setUint32(60, 0, true); r.setBigUint64(64, BigInt(e64), true); r.setUint32(72, 1, true);
      await this._w(new Uint8Array(r.buffer));
    }
    const z = new DataView(new ArrayBuffer(22));
    z.setUint32(0, 0x06054b50, true); z.setUint16(4, 0, true); z.setUint16(6, 0, true);
    z.setUint16(8, need64 ? 0xFFFF : n, true); z.setUint16(10, need64 ? 0xFFFF : n, true);
    z.setUint32(12, need64 ? 0xFFFFFFFF : cdSize, true); z.setUint32(16, need64 ? 0xFFFFFFFF : cdStart, true); z.setUint16(20, 0, true);
    await this._w(new Uint8Array(z.buffer));
  }
}
