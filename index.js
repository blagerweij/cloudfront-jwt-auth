'use strict';
const crypto = require('crypto');
var key = '-----BEGIN PUBLIC KEY-----\n' + // TODO: make public key configurable
'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
'-----END PUBLIC KEY-----';

const algorithmMap = {
  HS: 'sha',
  RS: 'RSA-SHA'
};

function base64urlDecode(str) {
  return new Buffer(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape(str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
}

exports.handler = (event, context, callback) => {
    const cfrequest = event.Records[0].cf.request;
    const headers = cfrequest.headers;
    if (!headers.authorization) {
        context.fail('no auth header');
    } else {
        const token = headers.authorization[0].value.slice(7);
        const [headerSeg,payloadSeg,signatureSeg] = token.split('.',3);
        const header = JSON.parse(base64urlDecode(headerSeg));
        const payload = JSON.parse(base64urlDecode(payloadSeg));
        const signature = base64urlUnescape(signatureSeg);
        const algorithm = header.alg.slice(0,2); // first the characters indicate algorithm
        const method = algorithmMap[algorithm] + header.alg.slice(2); // map JWA algorithm name to NodeJS implementation
        const input = [headerSeg, payloadSeg].join('.');
        if (algorithm === 'HS') { // HMAC or symmetric algorithm ?
          if (signature !== crypto.createHmac(method, key).update(input).digest('base64')) context.fail('Invalid signature');
        } else {
          if (!crypto.createVerify(method).update(input).verify(key, signature, 'base64')) context.fail('Invalid signature');
        }
        if (payload.exp && Date.now() > payload.exp*1000) context.fail('Token expired');
        delete cfrequest.headers.authorization;
        callback(null, cfrequest);
        return true;
    }
};
