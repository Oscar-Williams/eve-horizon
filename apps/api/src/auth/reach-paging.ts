/**
 * Pages a listing for a caller who reaches only part of it (P1-6): fetches
 * pages internally until `limit` items the caller reaches, or the end, and
 * takes the next cursor from the last item the caller sees, so a cursor
 * never names an item outside their reach. When `scanCap` items have been
 * scanned, the listing continues after the last visible item, or ends when
 * none was visible.
 */
export async function pageWithinReach<T, C>(params: {
  limit: number;
  start: C | undefined;
  /** One page from the source, and its own next cursor (null at the end). */
  fetch: (cursor: C | undefined) => Promise<{ items: T[]; next: C | null }>;
  visible: (item: T) => boolean;
  cursorOf: (item: T) => C;
  scanCap: number;
}): Promise<{ items: T[]; next: C | null; hidden: number }> {
  const items: T[] = [];
  let cursor = params.start;
  let scanned = 0;
  let hidden = 0;
  while (scanned < params.scanCap) {
    const page = await params.fetch(cursor);
    for (const item of page.items) {
      scanned += 1;
      if (!params.visible(item)) {
        hidden += 1;
        continue;
      }
      items.push(item);
      if (items.length === params.limit) {
        return { items, next: params.cursorOf(item), hidden };
      }
    }
    if (page.next === null || page.items.length === 0) {
      return { items, next: null, hidden };
    }
    cursor = page.next;
  }
  return { items, next: items.length > 0 ? params.cursorOf(items[items.length - 1]) : null, hidden };
}
