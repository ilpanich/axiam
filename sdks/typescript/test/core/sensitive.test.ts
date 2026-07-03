import { inspect } from 'node:util';
import { describe, expect, it } from 'vitest';
import { REDACTED, Sensitive } from '../../src/core/sensitive.js';

describe('Sensitive<T>', () => {
  const RAW = 'super-secret-token-value';

  it('redacts via String()/toString()', () => {
    const s = new Sensitive(RAW);
    expect(String(s)).toBe(REDACTED);
    expect(String(s)).not.toContain(RAW);
  });

  it('redacts via JSON.stringify', () => {
    const s = new Sensitive(RAW);
    const json = JSON.stringify({ t: s });
    expect(json).toContain(REDACTED);
    expect(json).not.toContain(RAW);
  });

  it('redacts via util.inspect (console.log path)', () => {
    const s = new Sensitive(RAW);
    const inspected = inspect(s);
    expect(inspected).toContain(REDACTED);
    expect(inspected).not.toContain(RAW);
  });

  it('exposes the raw value only via expose()', () => {
    const s = new Sensitive(RAW);
    expect(s.expose()).toBe(RAW);
  });
});
