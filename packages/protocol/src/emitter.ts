// Minimal typed event emitter that works the same in browsers and Node.

type Listener<A extends unknown[]> = (...args: A) => void;

export class Emitter<Events extends Record<string, unknown[]>> {
  #listeners = new Map<keyof Events, Set<Listener<never>>>();

  on<K extends keyof Events>(event: K, fn: Listener<Events[K]>): () => void {
    let set = this.#listeners.get(event);
    if (!set) this.#listeners.set(event, (set = new Set()));
    set.add(fn as Listener<never>);
    return () => set.delete(fn as Listener<never>);
  }

  once<K extends keyof Events>(event: K, fn: Listener<Events[K]>): () => void {
    const off = this.on(event, ((...args: Events[K]) => {
      off();
      fn(...args);
    }) as Listener<Events[K]>);
    return off;
  }

  protected emit<K extends keyof Events>(event: K, ...args: Events[K]): void {
    const set = this.#listeners.get(event);
    if (!set) return;
    for (const fn of [...set]) (fn as Listener<Events[K]>)(...args);
  }
}

/** setTimeout that never keeps a Node process alive on its own. */
export function weakTimeout(fn: () => void, ms: number): ReturnType<typeof setTimeout> {
  const t = setTimeout(fn, ms);
  (t as { unref?: () => void }).unref?.();
  return t;
}

export function weakInterval(fn: () => void, ms: number): ReturnType<typeof setInterval> {
  const t = setInterval(fn, ms);
  (t as { unref?: () => void }).unref?.();
  return t;
}
