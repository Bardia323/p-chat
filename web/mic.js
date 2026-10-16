// The microphone's samples, 20 ms at a time, handed to the page to encode
// (web/call.js) where a track gives no frames of its own (Safari).
class Mic extends AudioWorkletProcessor {
  constructor() {
    super();
    this.size = Math.round(sampleRate / 50);
    this.buf = new Float32Array(this.size);
    this.at = 0;
  }
  process(inputs) {
    const ch = inputs[0]?.[0];
    if (!ch) return true;
    for (let i = 0; i < ch.length; i++) {
      this.buf[this.at++] = ch[i];
      if (this.at === this.size) {
        this.port.postMessage(this.buf, [this.buf.buffer]);
        this.buf = new Float32Array(this.size);
        this.at = 0;
      }
    }
    return true;
  }
}
registerProcessor('p-chat-mic', Mic);
