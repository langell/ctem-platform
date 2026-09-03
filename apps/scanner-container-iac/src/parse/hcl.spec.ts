import { describe, expect, it } from 'vitest';
import { HclParseError, parseHclResources, parseTfJsonResources } from './hcl';

describe('parseHclResources', () => {
  it('extracts two resources from one file without collapsing them', () => {
    const resources = parseHclResources(`
resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
  acl    = "public-read"
}
resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
  acl    = "public-read-write"
}
`);
    expect(resources.map((r) => r.address)).toEqual(['aws_s3_bucket.logs', 'aws_s3_bucket.assets']);
    expect(resources[0]?.attributes.acl).toBe('public-read');
  });

  it('parses nested ingress blocks and lists', () => {
    const [sg] = parseHclResources(`
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`);
    const ingress = sg?.attributes.ingress as Array<Record<string, unknown>>;
    expect(ingress[0]?.from_port).toBe(22);
    expect(ingress[0]?.cidr_blocks).toEqual(['0.0.0.0/0']);
  });

  it('skips module blocks instead of fetching a registry source', () => {
    const resources = parseHclResources(`
module "s3" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"
}
resource "aws_ebs_volume" "data" {
  encrypted = false
}
`);
    expect(resources.map((r) => r.address)).toEqual(['aws_ebs_volume.data']);
  });

  it('fails closed on unclosed resource blocks', () => {
    expect(() =>
      parseHclResources(`resource "aws_s3_bucket" "broken" {
  acl =
`),
    ).toThrow(HclParseError);
  });
});

describe('parseTfJsonResources', () => {
  it('reads terraform JSON resource maps', () => {
    const resources = parseTfJsonResources(
      JSON.stringify({
        resource: {
          aws_s3_bucket: {
            logs: { acl: 'public-read' },
          },
        },
      }),
    );
    expect(resources).toEqual([
      expect.objectContaining({ address: 'aws_s3_bucket.logs', attributes: { acl: 'public-read' } }),
    ]);
  });
});
