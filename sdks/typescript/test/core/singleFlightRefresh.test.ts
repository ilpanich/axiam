import { afterEach, describe, expect, it } from 'vitest';
import { refreshOnce, resetRefreshGuard } from '../../src/core/singleFlightRefresh.js';

afterEach(() => {
  resetRefreshGuard();
});

function tickingRefresh(counter: { count: number }): () => Promise<void> {
  return () =>
    new Promise((resolve) => {
      counter.count += 1;
      setTimeout(resolve, 0);
    });
}

describe('refreshOnce', () => {
  it('invokes doRefresh exactly once for 5 concurrent callers', async () => {
    const counter = { count: 0 };
    const doRefresh = tickingRefresh(counter);

    const results = await Promise.all([
      refreshOnce(doRefresh),
      refreshOnce(doRefresh),
      refreshOnce(doRefresh),
      refreshOnce(doRefresh),
      refreshOnce(doRefresh),
    ]);

    expect(results).toHaveLength(5);
    expect(counter.count).toBe(1);
  });

  it('invokes doRefresh again after the previous refresh has settled', async () => {
    const counter = { count: 0 };
    const doRefresh = tickingRefresh(counter);

    await refreshOnce(doRefresh);
    expect(counter.count).toBe(1);

    await refreshOnce(doRefresh);
    expect(counter.count).toBe(2);
  });

  it('clears the guard even when doRefresh rejects', async () => {
    const doRefresh = () => Promise.reject(new Error('refresh failed'));

    await expect(refreshOnce(doRefresh)).rejects.toThrow('refresh failed');

    const counter = { count: 0 };
    await refreshOnce(tickingRefresh(counter));
    expect(counter.count).toBe(1);
  });
});
