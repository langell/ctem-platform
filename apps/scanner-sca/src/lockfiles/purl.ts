/** Package URL helpers. Names are encoded the way OSV/purl expect, not as full URI components. */

export function purlFor(ecosystem: string, name: string, version: string): string {
  switch (ecosystem) {
    case 'npm':
      return npmPurl(name, version);
    case 'PyPI':
      return `pkg:pypi/${encodeSegment(name)}@${version}`;
    case 'crates.io':
      return `pkg:cargo/${encodeSegment(name)}@${version}`;
    case 'Go':
      return `pkg:golang/${name}@${version}`;
    case 'RubyGems':
      return `pkg:gem/${encodeSegment(name)}@${version}`;
    case 'Maven': {
      const [group, artifact] = name.includes(':') ? name.split(':') : [name, name];
      return `pkg:maven/${group}/${artifact}@${version}`;
    }
    case 'NuGet':
      return `pkg:nuget/${encodeSegment(name)}@${version}`;
    case 'Packagist':
      return `pkg:composer/${name}@${version}`;
    default:
      return `pkg:generic/${encodeSegment(name)}@${version}`;
  }
}

function npmPurl(name: string, version: string): string {
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash > 1) {
      const ns = name.slice(1, slash);
      const pkg = name.slice(slash + 1);
      return `pkg:npm/%40${encodeSegment(ns)}/${encodeSegment(pkg)}@${version}`;
    }
  }
  return `pkg:npm/${encodeSegment(name)}@${version}`;
}

function encodeSegment(value: string): string {
  return encodeURIComponent(value).replace(/%2F/g, '/');
}
