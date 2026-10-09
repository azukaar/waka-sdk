// Where the SDK keeps the hub session, the device key and server sessions.
// A storage is three async methods: get(key), set(key, value), delete(key).
// Values may be CryptoKey objects, so localStorage is not suitable.

/** Keeps everything in memory. For tests and short-lived scripts. */
export class MemoryStorage {
  #map = new Map()
  async get(key) { return this.#map.get(key) }
  async set(key, value) { this.#map.set(key, value) }
  async delete(key) { this.#map.delete(key) }
}

/** IndexedDB storage, the default in a browser or a Tauri webview. */
export class BrowserStorage {
  #db
  constructor(name = 'waka') {
    this.#db = new Promise((resolve, reject) => {
      const req = indexedDB.open(name, 1)
      req.onupgradeneeded = () => req.result.createObjectStore('kv')
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    })
  }

  async #run(mode, fn) {
    const db = await this.#db
    return new Promise((resolve, reject) => {
      const req = fn(db.transaction('kv', mode).objectStore('kv'))
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    })
  }

  get(key) { return this.#run('readonly', (s) => s.get(key)) }
  set(key, value) { return this.#run('readwrite', (s) => s.put(value, key)) }
  delete(key) { return this.#run('readwrite', (s) => s.delete(key)) }
}
