/** Minimal promise wrapper around one IndexedDB object store (string keys, structured-clone values). */

const DB_NAME = "parley";
const STORE = "records";

let dbPromise: Promise<IDBDatabase> | null = null;

function open(): Promise<IDBDatabase> {
  dbPromise ??= new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("transaction aborted"));
  });
}

export async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE).objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result as T | undefined);
    request.onerror = () => reject(request.error);
  });
}

/** Writes and deletes in a single atomic transaction. */
export async function idbWrite(puts: [string, unknown][], deletes: string[] = []): Promise<void> {
  const db = await open();
  const tx = db.transaction(STORE, "readwrite");
  const store = tx.objectStore(STORE);
  for (const [key, value] of puts) store.put(value, key);
  for (const key of deletes) store.delete(key);
  await done(tx);
}

export async function idbEntries<T>(): Promise<[string, T][]> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const out: [string, T][] = [];
    const request = db.transaction(STORE).objectStore(STORE).openCursor();
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return resolve(out);
      out.push([String(cursor.key), cursor.value as T]);
      cursor.continue();
    };
    request.onerror = () => reject(request.error);
  });
}

export async function idbClear(): Promise<void> {
  const db = await open();
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).clear();
  await done(tx);
}
