import { Button } from 'antd'
import { useState } from 'react'
import forge from 'node-forge'

function App() {
  const [ privKey, setPrivKey ] = useState('')
  const [ pubKey, setPubKey ] = useState('')
  const [ csrStr, setCsrStr ] = useState('')
  const [ generateKeyTimeMs, setGenerateKeyTimeMs ] = useState(-1)
  
  // Ref: https://gist.github.com/mholt/813db71291de8e45371fe7c4749df99c
  const pemEncode = (label: string, data: string) => {
    const base64encoded = btoa(data)
    const base64encodedWrapped = base64encoded.replace(/(.{64})/g, "$1\n")
    return `-----BEGIN ${label}-----\n${base64encodedWrapped}\n-----END ${label}-----`
  }

  const generateHandler = async () => {
    let start = Date.now()
    
    const rsaExponent = new Uint8Array([1,0,1])
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 4096,
        publicExponent: rsaExponent,
        hash: {name: 'SHA-256'}
      },
      true,
      ['sign', 'verify']
    )

    const privKeyPkcs8ArrBuf = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
    const privKeyPkcs8BinStr = String.fromCharCode.apply(null, [...new Uint8Array(privKeyPkcs8ArrBuf)])

    const pubKeyArrBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    const pubKeyBinStr = String.fromCharCode.apply(null, [...new Uint8Array(pubKeyArrBuf)])
    
    const privKeyPem = pemEncode("PRIVATE KEY", privKeyPkcs8BinStr)
    const pubKeyPem = pemEncode("PUBLIC KEY", pubKeyBinStr)

    setPrivKey(privKeyPem)
    setPubKey(pubKeyPem)

    // Using node-forge to create RSA keypair significantly takes longer, need to tweak.
    // Use vanilla WebCrypto API for now
    // const rsaKeyPairs = forge.pki.rsa.generateKeyPair({bits: 4096, workers: -1})
    // setPrivKey(forge.pki.privateKeyToPem(rsaKeyPairs.privateKey))

    setGenerateKeyTimeMs(Date.now() - start)

    const csr = forge.pki.createCertificationRequest()
    csr.publicKey = forge.pki.publicKeyFromPem(pubKeyPem)
    csr.setSubject([
      {
        name: 'commonName',
        value: 'someone@example.com',
        valueTagClass: 12 as forge.asn1.Class
      }
    ])
    csr.sign(forge.pki.privateKeyFromPem(privKeyPem))
    
    setCsrStr(forge.pki.certificationRequestToPem(csr))
  }

  return (
    <>
      <Button type='primary' onClick={generateHandler}>Generate</Button>
      {
        generateKeyTimeMs !== -1 ? <p>RSA key pair generation took: {generateKeyTimeMs}ms</p> : null
      }
      {
        privKey ? <pre>{privKey}</pre> : null
      }
      {
        pubKey ? <pre>{pubKey}</pre> : null
      }
      {
        csrStr ? <pre>{csrStr}</pre> : null
      }
    </>
  )
}

export default App
