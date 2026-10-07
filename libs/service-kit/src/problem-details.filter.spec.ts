import { HttpException } from '@nestjs/common';
import { ArgumentsHost } from '@nestjs/common/interfaces';
import { describe, expect, it, vi } from 'vitest';
import { ProblemDetailsFilter } from './problem-details.filter';

function run(exception: unknown) {
  const json = vi.fn();
  const status = vi.fn(() => ({ json }));
  const host = {
    switchToHttp: () => ({
      getResponse: () => ({ status }),
      getRequest: () => ({}),
    }),
  } as unknown as ArgumentsHost;
  new ProblemDetailsFilter().catch(exception, host);
  return { status: status.mock.calls[0]?.[0], body: json.mock.calls[0]?.[0] as Record<string, unknown> };
}

describe('ProblemDetailsFilter', () => {
  it('passes a urn:ctem:problem type through and prefers detail over message', () => {
    const result = run(
      new HttpException(
        {
          type: 'urn:ctem:problem:invite-already-in-org',
          title: 'You already belong to an organization',
          detail: 'Ask an admin of your current organization to remove you, then open this invite again.',
          message: 'not the detail',
        },
        409,
      ),
    );
    expect(result.status).toBe(409);
    expect(result.body.type).toBe('urn:ctem:problem:invite-already-in-org');
    expect(result.body.title).toBe('You already belong to an organization');
    expect(result.body.detail).toBe(
      'Ask an admin of your current organization to remove you, then open this invite again.',
    );
  });

  it('uses about:blank for any other type and detail from message when detail is absent', () => {
    for (const type of [undefined, 'about:blank', 'urn:ctem:problem:Invite', 'https://example.test/problem', '']) {
      const result = run(new HttpException({ type, message: 'from message' }, 400));
      expect(result.body.type).toBe('about:blank');
      expect(result.body.detail).toBe('from message');
    }
    const plain = run(new HttpException('plain', 403));
    expect(plain.body.type).toBe('about:blank');
    expect(plain.body.detail).toBeUndefined();
    expect(plain.body.title).toBe('plain');
  });
});
