import { describe, it, expect } from 'vitest';
import { matchPath, checkPathCoverage } from '../path-match.js';

describe('Federation path matching', () => {
  it('matches exact paths', () => {
    expect(matchPath(
      'Property:/energyEfficiency/certificate',
      'Property:/energyEfficiency/certificate'
    )).toBe(true);
  });

  it('rejects non-matching exact paths', () => {
    expect(matchPath(
      'Property:/energyEfficiency/certificate',
      'Property:/energyEfficiency/rating'
    )).toBe(false);
  });

  it('matches wildcard paths', () => {
    expect(matchPath(
      'Title:/registerExtract/*',
      'Title:/registerExtract/proprietorship'
    )).toBe(true);

    expect(matchPath(
      'Title:/registerExtract/*',
      'Title:/registerExtract/charges/0'
    )).toBe(true);
  });

  it('wildcard does not match parent', () => {
    expect(matchPath(
      'Title:/registerExtract/*',
      'Title:/registerExtract'
    )).toBe(false);
  });

  it('wildcard does not match different entity', () => {
    expect(matchPath(
      'Title:/registerExtract/*',
      'Property:/registerExtract/something'
    )).toBe(false);
  });
});

describe('Federation path coverage', () => {
  it('reports full coverage', () => {
    const result = checkPathCoverage(
      ['Property:/energyEfficiency/*', 'Property:/floodRisk/*'],
      ['Property:/energyEfficiency/certificate', 'Property:/floodRisk/riverAndSea']
    );

    expect(result.covered).toHaveLength(2);
    expect(result.uncovered).toHaveLength(0);
  });

  it('reports partial coverage', () => {
    const result = checkPathCoverage(
      ['Property:/energyEfficiency/*'],
      ['Property:/energyEfficiency/certificate', 'Property:/floodRisk/riverAndSea']
    );

    expect(result.covered).toEqual(['Property:/energyEfficiency/certificate']);
    expect(result.uncovered).toEqual(['Property:/floodRisk/riverAndSea']);
  });
});
