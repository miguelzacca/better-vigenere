export interface VigenereOptions {
  encoding?: BufferEncoding
}

export interface GenerateKey extends VigenereOptions {
  length?: number
}

interface ProcessText {
  input: string
  key: string
  iv?: string
  encrypt?: boolean
}

export class Vigenere {
  static #IV_LENGTH = 16

  #chars: string[]
  #encoding: BufferEncoding

  #generateRandomChars() {
    const chars = Array.from({ length: 255 }, (_, i) => String.fromCharCode(i))

    for (let i = 0; i < chars.length; i++) {
      const j = Math.floor(Math.random() * (i + 1))
      const tmp = chars[i]
      chars[i] = chars[j]
      chars[j] = tmp
    }

    return chars
  }

  constructor(options?: VigenereOptions) {
    this.#encoding = options?.encoding || 'utf-8'
    this.#chars = this.#generateRandomChars()
  }

  #processText({ input, key, iv, encrypt }: ProcessText) {
    let output = ''

    for (let i = 0; i < input.length; i++) {
      const leftIndex = this.#chars.indexOf(input[i])
      const rightIndex = this.#chars.indexOf(key[i % key.length])
      const ivIndex = iv ? this.#chars.indexOf(iv[i % iv.length]) : 0

      const calc = encrypt ? leftIndex + rightIndex : leftIndex - rightIndex
      const increment = encrypt ? ivIndex : this.#chars.length * 2 - ivIndex

      const newIndex = (calc + increment) % this.#chars.length
      output += this.#chars[newIndex]
    }

    return output
  }

  #derivedKey(key: string, iv: string) {
    return this.#processText({ input: key, key: iv, encrypt: true })
  }

  generateKey(options?: GenerateKey) {
    const encoding = options?.encoding || 'utf-8'
    const length = options?.length || Vigenere.#IV_LENGTH

    let key = ''

    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * this.#chars.length)
      key += this.#chars[randomIndex]
    }

    return Buffer.from(key).toString(encoding)
  }

  encrypt(plainText: string, key: string) {
    const iv = this.generateKey()
    const derivedKey = this.#derivedKey(key, iv)

    const output = this.#processText({
      input: plainText,
      key: derivedKey,
      iv,
      encrypt: true,
    })

    const payload = iv.concat(output)
    return Buffer.from(payload).toString(this.#encoding)
  }

  decrypt(cipherText: string, key: string) {
    const payload = Buffer.from(cipherText, this.#encoding).toString()

    const iv = payload.slice(0, Vigenere.#IV_LENGTH)
    const input = payload.slice(Vigenere.#IV_LENGTH)

    const derivedKey = this.#derivedKey(key, iv)
    return this.#processText({ input, key: derivedKey, iv })
  }
}
