/**
 * Small AWS Query/REST XML helpers. Enough to inventory EC2/S3/STS — not a
 * general XML parser.
 */

export function xmlTag(xml: string, tag: string): string | undefined {
  const blocks = extractTagBlocks(xml, tag);
  const first = blocks[0];
  return first === undefined ? undefined : first.trim();
}

export function xmlTags(xml: string, tag: string): string[] {
  return extractTagBlocks(xml, tag).map((b) => b.trim());
}

export function extractTagBlocks(xml: string, tag: string): string[] {
  const blocks: string[] = [];
  const close = `</${tag}>`;
  let i = 0;
  while (i < xml.length) {
    const open = findOpenTag(xml, tag, i);
    if (!open) break;
    if (open.selfClosing) {
      i = open.end;
      continue;
    }
    let depth = 1;
    let j = open.end;
    let contentEnd = -1;
    while (j < xml.length && depth > 0) {
      const nextOpen = findOpenTag(xml, tag, j);
      const nextClose = xml.toLowerCase().indexOf(close.toLowerCase(), j);
      if (nextClose < 0) return blocks;
      if (nextOpen && nextOpen.start < nextClose) {
        if (!nextOpen.selfClosing) depth += 1;
        j = nextOpen.end;
      } else {
        depth -= 1;
        if (depth === 0) contentEnd = nextClose;
        j = nextClose + close.length;
      }
    }
    if (contentEnd < 0) break;
    blocks.push(xml.slice(open.end, contentEnd));
    i = contentEnd + close.length;
  }
  return blocks;
}

function findOpenTag(
  xml: string,
  tag: string,
  from: number,
): { start: number; end: number; selfClosing: boolean } | null {
  const needle = `<${tag}`;
  let idx = from;
  const lower = xml.toLowerCase();
  const needleLower = needle.toLowerCase();
  while (idx < xml.length) {
    const start = lower.indexOf(needleLower, idx);
    if (start < 0) return null;
    const after = start + needle.length;
    const ch = xml[after];
    if (ch !== '>' && ch !== ' ' && ch !== '\n' && ch !== '\t' && ch !== '/' && ch !== '\r') {
      idx = after;
      continue;
    }
    const gt = xml.indexOf('>', after);
    if (gt < 0) return null;
    return { start, end: gt + 1, selfClosing: xml[gt - 1] === '/' };
  }
  return null;
}

export function xmlNextToken(xml: string): string | undefined {
  return xmlTag(xml, 'nextToken') || xmlTag(xml, 'NextToken') || xmlTag(xml, 'ContinuationToken');
}

export function xmlIsTruncated(xml: string): boolean {
  const flag = xmlTag(xml, 'IsTruncated') || xmlTag(xml, 'isTruncated');
  return flag?.toLowerCase() === 'true';
}
