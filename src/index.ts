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
  static #BYTE_RANGE = 65536
  #IV_LENGTH: ByteSize

  static get ENCODING(): 'utf16le' {
    return 'utf16le'
  }

  constructor(options?: VigenereOptions) {
    this.#IV_LENGTH = options?.ivLength || 16
  }

  #adjustLength<T extends Buffer | number>(data: T): T {
    if (typeof data === 'number') {
      return (data & 1 ? data + 1 : data) as T
    }

    if (data.length & 1) {
      return Buffer.concat([data, Buffer.alloc(1, 0x20)]) as T
    }

    return data
  }

  #utf8To16le(buffer: Buffer): Buffer {
    return Buffer.from(buffer.toString(), Vigenere.ENCODING)
  }

  #processBytes({ input, key, iv, encrypt }: ProcessBytes): Buffer {
    const output = Buffer.allocUnsafe(input.length)

    const keyLength = key.length / 2
    const ivLength = iv ? iv.length / 2 : 0
    const ivIsDefined = iv !== undefined

    for (let i = 0; i < input.length / 2; i++) {
      const offset = i * 2

      const inputByte = input.readUint16LE(offset)
      const keyByte = key.readUint16LE((i % keyLength) * 2)
      const ivByte = ivIsDefined ? iv.readUint16LE((i & (ivLength - 1)) * 2) : 0

      const calc = encrypt ? inputByte + keyByte : inputByte - keyByte
      const increment = encrypt ? ivByte : Vigenere.#BYTE_RANGE - ivByte

      const newByte = calc + increment
      const normalized = (newByte + Vigenere.#BYTE_RANGE) % Vigenere.#BYTE_RANGE

      output.writeUint16LE(normalized, offset)
    }

    return output
  }

  #derivedKey(key: Buffer, iv: Buffer): Buffer {
    return this.#processBytes({ input: key, key: iv, encrypt: true })
  }

  generateKey(length: number): Buffer {
    const adjustedLength = this.#adjustLength(length)
    const key = Buffer.allocUnsafe(adjustedLength)

    for (let i = 0; i < adjustedLength / 2; i++) {
      key.writeUint16LE((Math.random() * Vigenere.#BYTE_RANGE) | 0, i * 2)
    }

    return key
  }

  encrypt(plainText: Buffer, key: Buffer): Buffer {
    const adjustedTextLength = this.#adjustLength(plainText)
    const text = this.#utf8To16le(adjustedTextLength)
    const iv = this.generateKey(this.#IV_LENGTH)
    const derivedKey = this.#derivedKey(key, iv)

    const output = this.#processBytes({
      input: text,
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
