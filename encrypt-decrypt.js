const { padding } = require('aes-js')
const crypto=require('crypto')
const fs=require('fs')

const {publicKey,privateKey}=crypto.generateKeyPairSync("rsa",{
    modulusLength:2048,
})

function encrypttext(plainText)
{
    return crypto.publicEncrypt({
        key:fs.readFileSync('public_key.pem','utf-8'),
        padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash:'sha256'
    },
    Buffer.from(plainText)
    )
}

const plainText="simple text"

const encryptedText=encrypttext(plainText)
console.log(encryptedText.toString('base64'))

function decrypttext(encryptedText)
{
    return crypto.privateDecrypt(
        {
            key:fs.readFileSync('private_key.pem','utf-8'),
            padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash:'sha256'
        },
        encryptedText
    )
}

const decryptedText = decrypttext(encryptedText)
console.log('decrypted text:', decryptedText.toString())

//signing and verification
const signature = crypto.sign("sha256", Buffer.from(plainText), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });
  
  console.log(signature.toString("base64"));
  const isVerified = crypto.verify(
    "sha256",
    Buffer.from(plainText),
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    signature
  );
  
  console.log("signature verified: ", isVerified);