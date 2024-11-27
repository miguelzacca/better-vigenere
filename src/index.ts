type ByteSize = 8 | 16 | 32 | 64 | 128 | 256

interface IVigenere {
  generateKey(length: number): Buffer
  encrypt(plainText: Buffer, key: Buffer): Buffer
  decrypt(cipherText: Buffer, key: Buffer): Buffer
}

interface ProcessBytes {
  input: Buffer
  key: Buffer
  iv?: Buffer
  encrypt?: boolean
}

interface VigenereOptions {
  ivLength?: ByteSize
}

export class Vigenere implements IVigenere {
  static #BYTE_RANGE = 256
  #IV_LENGTH: ByteSize

  constructor(options?: VigenereOptions) {
    this.#IV_LENGTH = options?.ivLength || 16
  }

  #processBytes({ input, key, iv, encrypt }: ProcessBytes) {
    const output = Buffer.allocUnsafe(input.length)

    const keyLength = key.length
    const ivLength = iv ? iv.length : 0
    const ivIsDefined = iv !== undefined

    for (let i = 0; i < input.length; i++) {
      const keyByte = key[i % keyLength]
      const ivByte = ivIsDefined ? iv[i & (ivLength - 1)] : 0

      const calc = encrypt ? input[i] + keyByte : input[i] - keyByte
      const increment = encrypt ? ivByte : Vigenere.#BYTE_RANGE - ivByte

      output[i] = (calc + increment) % Vigenere.#BYTE_RANGE
    }

    return output
  }

  #derivedKey(key: Buffer, iv: Buffer) {
    return this.#processBytes({ input: key, key: iv, encrypt: true })
  }

  generateKey(length: number): Buffer {
    const key = Buffer.allocUnsafe(length)

    for (let i = 0; i < length; i++) {
      key[i] = (Math.random() * Vigenere.#BYTE_RANGE) | 0
    }

    return key
  }

  encrypt(plainText: Buffer, key: Buffer): Buffer {
    const iv = this.generateKey(this.#IV_LENGTH)
    const derivedKey = this.#derivedKey(key, iv)

    const output = this.#processBytes({
      input: plainText,
      key: derivedKey,
      iv,
      encrypt: true,
    })

    return Buffer.concat([iv, output])
  }

  decrypt(cipherText: Buffer, key: Buffer): Buffer {
    const iv = cipherText.subarray(0, this.#IV_LENGTH)
    const input = cipherText.subarray(this.#IV_LENGTH)
    const derivedKey = this.#derivedKey(key, iv)
    return this.#processBytes({ input, key: derivedKey, iv })
  }
}
