import { describe, expect, it } from 'vitest';
import { nameFromNodeId, shortestPathsFromRoots } from './graph';

describe('shortestPathsFromRoots', () => {
  it('returns the shortest explanation on a diamond', () => {
    const edges = new Map([
      ['a@1', ['b@1', 'deep@1']],
      ['b@1', ['deep@1']],
      ['deep@1', []],
    ]);
    const paths = shortestPathsFromRoots(['a@1'], edges);
    expect(paths.get('deep@1')?.map(nameFromNodeId)).toEqual(['a', 'deep']);
  });

  it('survives cycles', () => {
    const edges = new Map([
      ['x@1', ['y@1']],
      ['y@1', ['x@1']],
    ]);
    const paths = shortestPathsFromRoots(['x@1'], edges);
    expect(paths.get('y@1')?.map(nameFromNodeId)).toEqual(['x', 'y']);
  });
});
