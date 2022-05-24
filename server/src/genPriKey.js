const {pool} = require("../dbConfig");
const crypto = require('crypto');
const { encodeString } = require("./lib/code");
const { byte2hexStr, base64EncodeToString, byteArray2hexStr } = require("./utils/bytes");
const {base64DecodeFromString, hexStr2byteArray} = require("./lib/code");
const {ADDRESS_PREFIX, ADDRESS_PREFIX_BYTE} = require("./utils/address");
const {encode58, decode58} = require("./lib/base58");
const EC = require('elliptic').ec;
const { keccak256 } = require('js-sha3');
const jsSHA = require("./lib/sha256");



//return address by bytes, pubBytes is byte[]
function computeAddress(pubBytes) {
  if (pubBytes.length === 65) {
    pubBytes = pubBytes.slice(1);
  }

  var hash = keccak256(pubBytes).toString();
  var addressHex = hash.substring(24);
  addressHex = ADDRESS_PREFIX + addressHex;
  return hexStr2byteArray(addressHex);
}

//return address by bytes, priKeyBytes is byte[]
function getAddressFromPriKey(priKeyBytes) {
  let pubBytes = getPubKeyFromPriKey(priKeyBytes);
  return computeAddress(pubBytes);
}

//return address by Base58Check String,
function getBase58CheckAddress(addressBytes) {
  var hash0 = SHA256(addressBytes);
  var hash1 = SHA256(hash0);
  var checkSum = hash1.slice(0, 4);
  checkSum = addressBytes.concat(checkSum);
  return encode58(checkSum);
}



//return pubkey by 65 bytes, priKeyBytes is byte[]
function getPubKeyFromPriKey(priKeyBytes) {
  var ec = new EC('secp256k1');
  var key = ec.keyFromPrivate(priKeyBytes, 'bytes');
  var pubkey = key.getPublic();
  var x = pubkey.x;
  var y = pubkey.y;
  var xHex = x.toString('hex');
  while (xHex.length < 64) {
    xHex = "0" + xHex;
  }
  var yHex = y.toString('hex');
  while (yHex.length < 64) {
    yHex = "0" + yHex;
  }
  var pubkeyHex = "04" + xHex + yHex;
  var pubkeyBytes = hexStr2byteArray(pubkeyHex);
  return pubkeyBytes;
}


//return 32 bytes
function SHA256(msgBytes) {
  let shaObj = new jsSHA("SHA-256", "HEX");
  let msgHex = byteArray2hexStr(msgBytes);
  shaObj.update(msgHex);
  let hashHex = shaObj.getHash("HEX");
  return hexStr2byteArray(hashHex);
}


function pkToAddress(privateKey) {
  let com_priKeyBytes = hexStr2byteArray(privateKey);
  let com_addressBytes = getAddressFromPriKey(com_priKeyBytes);
  return getBase58CheckAddress(com_addressBytes);
}


function genPriKey() {
  let ec = new EC('secp256k1');
  let key = ec.genKeyPair();
  let priKey = key.getPrivate();
  let priKeyHex = priKey.toString('hex');
  while (priKeyHex.length < 64) {
    priKeyHex = "0" + priKeyHex;
  }

  return hexStr2byteArray(priKeyHex);
}



let salt;
let saltHex;
let iv;
let cipherText;
let tronAddress;

const encryptPriKey = function(password, id, email ){
  const algorithm = 'aes-128-cbc';
  salt = crypto.randomBytes(16);
  iv= crypto.randomBytes(16);


  console.log('salt', salt.toString('hex'));
  console.log('iv', iv.toString('hex'));

  const priKeyBytes=genPriKey();
  const priKeyStr=byteArray2hexStr(priKeyBytes);

  tronAddress=pkToAddress(priKeyStr);

  var b64PriKey= Buffer.from(priKeyStr, 'hex').toString('base64');

  console.log("private key 1", priKeyStr);
  console.log(" base64 private key", b64PriKey);

  const derivedKeyBytes= crypto.scryptSync(password, salt, 16);

  console.log('derived key', derivedKeyBytes.toString('hex'));
   
  const cipher = crypto.createCipheriv(algorithm, derivedKeyBytes, iv);
  

  cipherText=  Buffer.concat([
    cipher.update(b64PriKey),
    cipher.final()
  ]).toString('base64')

  console.log('ciphertext', cipherText);
  saltHex=salt.toString('hex');

  return {tronAddress, saltHex, iv, cipherText};

};




function getPrivateKey(password, saltHex, iv, cipherText){
   
  const algorithm = 'aes-128-cbc';

  let salt2 = saltHex;
  const iv2 = iv;

  const derivedKeyBytes= crypto.scryptSync(password, salt2, 16);

  console.log("salt2", salt2.toString('hex'));
  console.log("iv2", iv2.toString('hex'));
  console.log('derived key 2', derivedKeyBytes.toString('hex'));

  if (cipherText === null || typeof cipherText === 'undefined' || cipherText === '') {
    return cipherText;
  }
  var decipher = crypto.createDecipheriv(algorithm, derivedKeyBytes, iv2)
  console.log("decipher", decipher.toString('hex'));
  const decipherText= Buffer.concat([
    decipher.update(cipherText, 'base64'), // Expect `text` to be a base64 string
    decipher.final()
  ]).toString()

  const decipherTextStr=Buffer.from(decipherText, 'base64').toString('hex');

  console.log(decipherTextStr);
  
  return decipherText;

  }


  module.exports={
      encryptPriKey,
      getPrivateKey
  }