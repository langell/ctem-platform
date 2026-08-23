import { Injectable } from '@nestjs/common';
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { loadEnv } from '@ctem/config';

/**
 * Raw scanner output, SBOMs and generated reports live in object storage, not in
 * Postgres. Findings keep only a key. Keys are org-prefixed so a bucket policy
 * or a lifecycle rule can be written per tenant.
 */
@Injectable()
export class ArtifactStore {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly sse: 'AES256' | 'aws:kms' | undefined;

  constructor() {
    const env = loadEnv();
    this.bucket = env.S3_BUCKET;
    // Scanner output routinely contains source snippets — production must never
    // leave it unencrypted. Dev MinIO has no KMS, so SSE stays off unless asked.
    const sse = env.S3_SSE ?? (env.NODE_ENV === 'production' ? 'AES256' : 'none');
    this.sse = sse === 'none' ? undefined : sse;
    this.client = new S3Client({
      region: env.S3_REGION,
      endpoint: env.S3_ENDPOINT,
      forcePathStyle: env.S3_FORCE_PATH_STYLE,
      credentials: {
        accessKeyId: env.S3_ACCESS_KEY_ID,
        secretAccessKey: env.S3_SECRET_ACCESS_KEY,
      },
    });
  }

  key(orgId: string, kind: 'scan' | 'sbom' | 'report' | 'evidence', ...parts: string[]): string {
    return [`org=${orgId}`, kind, ...parts].join('/');
  }

  async put(key: string, body: Buffer | string, contentType = 'application/json'): Promise<string> {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: contentType,
        ServerSideEncryption: this.sse,
      }),
    );
    return key;
  }

  async putJson(key: string, value: unknown): Promise<string> {
    return this.put(key, JSON.stringify(value), 'application/json');
  }

  async get(key: string): Promise<Buffer> {
    const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
    const chunks: Buffer[] = [];
    for await (const chunk of res.Body as AsyncIterable<Uint8Array>) {
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  }

  async getJson<T>(key: string): Promise<T> {
    return JSON.parse((await this.get(key)).toString('utf8')) as T;
  }
}
