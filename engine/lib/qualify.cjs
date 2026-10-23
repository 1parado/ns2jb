const crypto = require('node:crypto');

async function qualify(native) {
  const a = native.addresses;
  const check = (ok, message) => {if (!ok) throw Error(message);};
  const proof = {started: new Date().toISOString(), platform: a.platform};
  const code = await native.query(a.sdk);
  check(code.address === BigInt(a.sdk) && code.size === 0x5e1000n && code.type === 3 &&
    code.permissions === 5 && code.attributes === 0, 'The SDK mapping is unexpected.');
  proof.sdk = {address: code.address.toString(16), size: Number(code.size), type: code.type,
    permissions: code.permissions, attributes: code.attributes};
  const text = await native.read(a.sdk + 0x3f000n, 16);
  check(text.equals(Buffer.from('4154454e000000004154454e00000000', 'hex')), 'SDK text is unexpected.');
  proof.sdkText = text.toString('hex');
  const data = await native.query(a.sdkData);
  check(data.address === BigInt(a.sdkData) && data.size === 0x2c000n && data.type === 3 &&
    data.permissions === 3 && data.attributes === 0, 'The SDK data mapping is unexpected.');
  proof.sdkData = {address: data.address.toString(16), size: Number(data.size), type: data.type,
    permissions: data.permissions, attributes: data.attributes};
  return proof;
}

module.exports = {qualify};
