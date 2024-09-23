import { Button } from 'antd'
import { useState, useRef, useEffect } from 'react'
import forge from 'node-forge'

const RSA_KEY_SIZE = 4096;

function App() {
  const [ privKey, setPrivKey ] = useState('')
  const [ pubKey, setPubKey ] = useState('')
  const [ csrStr, setCsrStr ] = useState('')
  const [ generateKeyTimeMs, setGenerateKeyTimeMs ] = useState(-1)
  const [ fileDownloadURL, setFileDownloadURL ] = useState('')

  const downloadLinkRef = useRef<HTMLAnchorElement>(null)

  // Ref: https://gist.github.com/mholt/813db71291de8e45371fe7c4749df99c
  const pemEncode = (label: string, data: string) => {
    const base64encoded = btoa(data)
    const base64encodedWrapped = base64encoded.replace(/(.{64})/g, "$1\n")
    return `-----BEGIN ${label}-----\n${base64encodedWrapped}\n-----END ${label}-----`
  }

  const generateHandler = async () => {
    const start = Date.now()

    const rsaExponent = new Uint8Array([1,0,1])
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: RSA_KEY_SIZE,
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
    csr.setAttributes([
      {
        name: 'extensionRequest',
        extensions: [
          {
            name: 'subjectAltName',
            altNames: [
              // Ref: https://www.alvestrand.no/objectid/2.5.29.17.html
              // https://stackoverflow.com/questions/17172239/on-certificates-what-type-should-e-mail-addresses-be-when-in-subjectaltname
              // Email address should use rfc822 name
              {
                type: 1,
                value: 'someone@example.com',
              }
            ]
          }
        ]
      }
    ])
    csr.sign(forge.pki.privateKeyFromPem(privKeyPem))

    const csrVerified = csr.verify()
    if (!csrVerified) {
      // TODO: abort and show error message if verification fail
    }

    setCsrStr(forge.pki.certificationRequestToPem(csr))

    const privKeyFile = new Blob([privKeyPem], {type: 'application/pkcs8'})
    const downloadURL = URL.createObjectURL(privKeyFile)
    setFileDownloadURL(downloadURL)
  }

  useEffect(() => {
    if (fileDownloadURL) {
      downloadLinkRef!.current!.click()
      setFileDownloadURL('')
      window.URL.revokeObjectURL(fileDownloadURL)
    }
  }, [fileDownloadURL])

  return (
    <>
      <Button type='primary' onClick={generateHandler}>Generate</Button>
      {
        generateKeyTimeMs !== -1 ? <p>RSA key pair ({RSA_KEY_SIZE} bit) generation took: {generateKeyTimeMs}ms</p> : null
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
      {
        fileDownloadURL ? <a ref={downloadLinkRef} href={fileDownloadURL} download={`test-${new Date().toISOString()}.key`} style={{'display': 'none'}}></a> : null
      }
    </>
  )
}

export default App
