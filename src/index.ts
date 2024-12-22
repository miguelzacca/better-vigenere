type IVLength = 8 | 16 | 32 | 64 | 128 | 256

interface VigenereProperties {
  generateKey(length: number): Buffer
  encrypt(plainText: Buffer, key: Buffer): Buffer
  decrypt(cipherText: Buffer, key: Buffer): Buffer
}

interface ProcessEncrypt {
  input: Buffer
  key: Buffer
  iv?: Buffer
}

interface ProcessDecrypt {
  input: Buffer
  key: Buffer
  iv: Buffer
}

export interface VigenereOptions {
  ivLength?: IVLength
}

export class Vigenere implements VigenereProperties {
  static #I32_RANGE = 4294967296
  static #I8_RANGE = 256
  #IV_LENGTH: IVLength

  constructor(options?: VigenereOptions) {
    this.#IV_LENGTH = options?.ivLength || 16
  }

  #adjustLength<T extends Buffer | number>(data: T): [T, number] {
    const getPadding = (value: number) => {
      const overflow = 4 - (value % 4)
      return overflow === 4 ? 0 : overflow
    }

    if (typeof data === 'number') {
      const padding = getPadding(data)
      const newData = (data + padding) as T
      return [newData, padding]
    }

    const padding = getPadding(data.length)
    if (padding) {
      const newData = Buffer.concat([data, Buffer.alloc(padding, 0x20)]) as T
      return [newData, padding]
    }

    return [data, 0]
  }

  #processEncrypt({ input, key, iv }: ProcessEncrypt): Buffer {
    const output = Buffer.allocUnsafe(input.length * 4)

    const keyLength = key.length
    const ivLength = iv ? iv.length / 4 : 0
    const ivIsDefined = iv !== undefined

    for (let i = 0; i < input.length; i++) {
      const inputByte = input.readUint8(i)
      const keyByte = key[i % keyLength]
      const ivByte = ivIsDefined ? iv.readUint32LE((i & (ivLength - 1)) * 4) : 0

      const newByte = (inputByte + keyByte + ivByte) % Vigenere.#I32_RANGE
      const normalized = (newByte + Vigenere.#I32_RANGE) % Vigenere.#I32_RANGE

      output.writeUint32LE(normalized, i * 4)
    }

    return output
  }

  #processDecrypt({ input, key, iv }: ProcessDecrypt): Buffer {
    const output = Buffer.allocUnsafe(input.length / 4)

    const keyLength = key.length
    const ivLength = iv.length / 4

    for (let i = 0; i < output.length; i++) {
      const inputByte = input.readUint32LE(i * 4)
      const keyByte = key[i % keyLength]
      const ivByte = iv.readUint32LE((i & (ivLength - 1)) * 4)

      const newByte = (inputByte - keyByte - ivByte) % Vigenere.#I8_RANGE
      const normalized = (newByte + Vigenere.#I8_RANGE) % Vigenere.#I8_RANGE

      output[i] = normalized
    }

    return output
  }

  #derivedKey(key: Buffer, iv: Buffer): Buffer {
    return this.#processEncrypt({ input: key, key: iv })
  }

  generateKey(length: number): Buffer {
    const key = Buffer.allocUnsafe(length)

    for (let i = 0; i < length; i++) {
      key[i] = (Math.random() * Vigenere.#I8_RANGE) | 0
    }

    return key
  }

  encrypt(plainText: Buffer, key: Buffer): Buffer {
    const [text, padding] = this.#adjustLength(plainText)
    const iv = this.generateKey(this.#IV_LENGTH)
    const derivedKey = this.#derivedKey(key, iv)

    const output = this.#processEncrypt({
      input: text,
      key: derivedKey,
      iv,
    })

    return Buffer.concat([Buffer.alloc(1, padding), iv, output])
  }

  decrypt(cipherText: Buffer, key: Buffer): Buffer {
    const iv = cipherText.subarray(1, this.#IV_LENGTH + 1)
    const input = cipherText.subarray(this.#IV_LENGTH + 1)
    const derivedKey = this.#derivedKey(key, iv)
    const output = this.#processDecrypt({ input, key: derivedKey, iv })
    return output.subarray(0, -cipherText[0] || output.length)
  }
}
