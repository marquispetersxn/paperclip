/**
 * PetraS3Client — Sovereign S3-Compatible HTTP Client
 *
 * Replaces @aws-sdk/client-s3 and @aws-sdk/s3-request-presigner.
 * Zero npm dependencies — uses only node:crypto, node:http, node:https, node:url, node:buffer.
 *
 * Implements AWS Signature V4 signing for MinIO (and any S3-compatible endpoint).
 * Drop-in API shape matching @aws-sdk/client-s3 v3 command pattern.
 *
 * Supported commands:
 *   PutObjectCommand, GetObjectCommand, DeleteObjectCommand,
 *   HeadBucketCommand, CreateBucketCommand, HeadObjectCommand,
 *   ListObjectsV2Command
 *
 * Presigned URLs:
 *   getSignedUrl(client, command, { expiresIn }) — for GetObjectCommand only
 */

import { createHmac, createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { Readable } from 'node:stream';
import { URL } from 'node:url';
import { Buffer } from 'node:buffer';

// ─── Config ──────────────────────────────────────────────────────────────────

export interface PetraS3Config {
  endpoint: string;
  region?: string;
  credentials: {
    accessKeyId: string;
    secretAccessKey: string;
  };
  forcePathStyle?: boolean;
}

// ─── Command Input Types ─────────────────────────────────────────────────────

export interface PutObjectInput {
  Bucket: string;
  Key: string;
  Body?: Buffer | string | Readable | Uint8Array;
  ContentType?: string;
  Metadata?: Record<string, string>;
}

export interface GetObjectInput {
  Bucket: string;
  Key: string;
}

export interface DeleteObjectInput {
  Bucket: string;
  Key: string;
}

export interface HeadBucketInput {
  Bucket: string;
}

export interface CreateBucketInput {
  Bucket: string;
}

export interface HeadObjectInput {
  Bucket: string;
  Key: string;
}

export interface ListObjectsV2Input {
  Bucket: string;
  Prefix?: string;
  Delimiter?: string;
  MaxKeys?: number;
  ContinuationToken?: string;
}

// ─── Command Output Types ────────────────────────────────────────────────────

export interface GetObjectOutput {
  Body: Readable & { transformToString(): Promise<string> };
  ContentType?: string;
  ContentLength?: number;
  LastModified?: Date;
  ETag?: string;
  Metadata?: Record<string, string>;
}

export interface HeadObjectOutput {
  ContentType?: string;
  ContentLength?: number;
  LastModified?: Date;
  ETag?: string;
  Metadata?: Record<string, string>;
}

export interface ListObjectsV2Output {
  Contents?: Array<{
    Key?: string;
    Size?: number;
    LastModified?: Date;
    ETag?: string;
  }>;
  KeyCount?: number;
  IsTruncated?: boolean;
  NextContinuationToken?: string;
  CommonPrefixes?: Array<{ Prefix?: string }>;
}

// ─── Command Classes (AWS SDK v3 drop-in) ────────────────────────────────────

export class PutObjectCommand {
  readonly _type = 'PutObject' as const;
  constructor(public readonly input: PutObjectInput) {}
}

export class GetObjectCommand {
  readonly _type = 'GetObject' as const;
  constructor(public readonly input: GetObjectInput) {}
}

export class DeleteObjectCommand {
  readonly _type = 'DeleteObject' as const;
  constructor(public readonly input: DeleteObjectInput) {}
}

export class HeadBucketCommand {
  readonly _type = 'HeadBucket' as const;
  constructor(public readonly input: HeadBucketInput) {}
}

export class CreateBucketCommand {
  readonly _type = 'CreateBucket' as const;
  constructor(public readonly input: CreateBucketInput) {}
}

export class HeadObjectCommand {
  readonly _type = 'HeadObject' as const;
  constructor(public readonly input: HeadObjectInput) {}
}

export class ListObjectsV2Command {
  readonly _type = 'ListObjectsV2' as const;
  constructor(public readonly input: ListObjectsV2Input) {}
}

// Union type for all commands
export type S3Command =
  | PutObjectCommand
  | GetObjectCommand
  | DeleteObjectCommand
  | HeadBucketCommand
  | CreateBucketCommand
  | HeadObjectCommand
  | ListObjectsV2Command;

// ─── AWS Signature V4 Implementation ────────────────────────────────────────

/** Format a Date as YYYYMMDD */
function formatDate(date: Date): string {
  return date.toISOString().slice(0, 10).replace(/-/g, '');
}

/** Format a Date as YYYYMMDDTHHMMSSZ (ISO8601 basic) */
function formatDateTime(date: Date): string {
  return date.toISOString().replace(/[:\-]|\.\d{3}/g, '').replace('T', 'T').slice(0, 16) + 'Z';
}

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function hexEncode(buf: Buffer): string {
  return buf.toString('hex');
}

/** Derive the V4 signing key for a given date/region/service */
function getSigningKey(secretKey: string, date: string, region: string, service: string): Buffer {
  const kDate = hmacSha256(`AWS4${secretKey}`, date);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  return kSigning;
}

interface SigningOptions {
  method: string;
  url: URL;
  headers: Record<string, string>;
  bodyHash: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  service: string;
  date: Date;
}

/**
 * Compute AWS Signature V4 Authorization header.
 * Returns the Authorization header value and x-amz-date header value.
 */
function signRequest(opts: SigningOptions): { authorization: string; amzDate: string } {
  const {
    method, url, headers, bodyHash,
    accessKeyId, secretAccessKey, region, service, date,
  } = opts;

  const amzDate = formatDateTime(date);
  const dateOnly = formatDate(date);

  // Canonical headers — must be sorted and lowercased
  const allHeaders: Record<string, string> = {
    ...headers,
    'x-amz-date': amzDate,
    host: url.host,
  };

  const sortedHeaderNames = Object.keys(allHeaders).sort();
  const canonicalHeaders = sortedHeaderNames
    .map((k) => `${k.toLowerCase()}:${allHeaders[k].trim()}\n`)
    .join('');
  const signedHeaders = sortedHeaderNames.map((k) => k.toLowerCase()).join(';');

  // Canonical query string — percent-encode and sort
  const queryParams = Array.from(url.searchParams.entries())
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');

  // Canonical URI — path needs to be percent-encoded but slashes preserved
  const canonicalUri = url.pathname || '/';

  const canonicalRequest = [
    method,
    canonicalUri,
    queryParams,
    canonicalHeaders,
    signedHeaders,
    bodyHash,
  ].join('\n');

  const credentialScope = `${dateOnly}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const signingKey = getSigningKey(secretAccessKey, dateOnly, region, service);
  const signature = hexEncode(hmacSha256(signingKey, stringToSign));

  const authorization = [
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}`,
    `SignedHeaders=${signedHeaders}`,
    `Signature=${signature}`,
  ].join(', ');

  return { authorization, amzDate };
}

// ─── HTTP Request Helper ─────────────────────────────────────────────────────

interface RawResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer;
  stream: Readable;
}

function makeRequest(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body?: Buffer,
  streaming?: false,
): Promise<RawResponse>;
function makeRequest(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: Buffer | undefined,
  streaming: true,
): Promise<{ statusCode: number; headers: Record<string, string>; stream: Readable; body: Buffer }>;
function makeRequest(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body?: Buffer,
  streaming?: boolean,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const requestFn = isHttps ? httpsRequest : httpRequest;

    const options = {
      hostname: url.hostname,
      port: url.port ? parseInt(url.port, 10) : (isHttps ? 443 : 80),
      path: url.pathname + (url.search || ''),
      method,
      headers,
    };

    const req = requestFn(options, (res) => {
      const respHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (typeof v === 'string') respHeaders[k] = v;
        else if (Array.isArray(v)) respHeaders[k] = v.join(', ');
      }

      if (streaming) {
        // Return stream immediately without buffering
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: respHeaders,
          stream: res as unknown as Readable,
          body: Buffer.alloc(0), // unused in streaming mode
        });
        return;
      }

      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const responseBody = Buffer.concat(chunks);
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: respHeaders,
          body: responseBody,
          stream: Readable.from([responseBody]),
        });
      });
      res.on('error', reject);
    });

    req.on('error', reject);

    if (body && body.length > 0) {
      req.write(body);
    }
    req.end();
  });
}

// ─── Simple XML parser for S3 responses ──────────────────────────────────────

/** Extract text content of all matching tags from XML string */
function extractXmlTags(xml: string, tag: string): string[] {
  const results: string[] = [];
  const regex = new RegExp(`<${tag}>(.*?)<\/${tag}>`, 'gs');
  let match;
  while ((match = regex.exec(xml)) !== null) {
    results.push(match[1]);
  }
  return results;
}

/** Extract first matching tag value */
function extractXmlTag(xml: string, tag: string): string | undefined {
  const results = extractXmlTags(xml, tag);
  return results[0];
}

/** Parse ListObjectsV2 XML response */
function parseListObjectsV2(xml: string): ListObjectsV2Output {
  const contents: ListObjectsV2Output['Contents'] = [];

  // Extract each <Contents> block
  const contentsBlocks = extractXmlTags(xml, 'Contents');
  for (const block of contentsBlocks) {
    const key = extractXmlTag(block, 'Key');
    const sizeStr = extractXmlTag(block, 'Size');
    const lastModifiedStr = extractXmlTag(block, 'LastModified');
    const etag = extractXmlTag(block, 'ETag');

    contents.push({
      Key: key,
      Size: sizeStr ? parseInt(sizeStr, 10) : undefined,
      LastModified: lastModifiedStr ? new Date(lastModifiedStr) : undefined,
      ETag: etag?.replace(/&quot;/g, '"'),
    });
  }

  const keyCountStr = extractXmlTag(xml, 'KeyCount');
  const isTruncatedStr = extractXmlTag(xml, 'IsTruncated');
  const nextToken = extractXmlTag(xml, 'NextContinuationToken');

  const commonPrefixes: Array<{ Prefix?: string }> = [];
  const prefixBlocks = extractXmlTags(xml, 'CommonPrefixes');
  for (const block of prefixBlocks) {
    const prefix = extractXmlTag(block, 'Prefix');
    if (prefix) commonPrefixes.push({ Prefix: prefix });
  }

  return {
    Contents: contents,
    KeyCount: keyCountStr ? parseInt(keyCountStr, 10) : contents.length,
    IsTruncated: isTruncatedStr === 'true',
    NextContinuationToken: nextToken,
    CommonPrefixes: commonPrefixes.length > 0 ? commonPrefixes : undefined,
  };
}

// ─── URL Builder ─────────────────────────────────────────────────────────────

function buildObjectUrl(config: PetraS3Config, bucket: string, key?: string): URL {
  const base = config.endpoint.endsWith('/')
    ? config.endpoint.slice(0, -1)
    : config.endpoint;

  // Path-style: http://endpoint/bucket/key
  const path = key ? `/${bucket}/${encodeURIComponent(key).replace(/%2F/g, '/')}` : `/${bucket}`;
  return new URL(`${base}${path}`);
}

// ─── Body normalization ───────────────────────────────────────────────────────

async function bodyToBuffer(body: PutObjectInput['Body']): Promise<Buffer> {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  if (body instanceof Uint8Array) return Buffer.from(body);
  // Readable stream
  const chunks: Buffer[] = [];
  for await (const chunk of body as AsyncIterable<Buffer>) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

// ─── S3 Error thrower ────────────────────────────────────────────────────────

function throwS3Error(statusCode: number, body: Buffer, operation: string): never {
  const text = body.toString('utf8');
  // Try to extract error code from XML
  const code = extractXmlTag(text, 'Code') ?? String(statusCode);
  const message = extractXmlTag(text, 'Message') ?? text.slice(0, 200);
  const err = new Error(`${operation} failed: ${code} — ${message}`);
  (err as NodeJS.ErrnoException).code = code;
  throw err;
}

// ─── PetraS3Client ───────────────────────────────────────────────────────────

export class PetraS3Client {
  private readonly config: Required<PetraS3Config>;

  constructor(config: PetraS3Config) {
    this.config = {
      endpoint: config.endpoint,
      region: config.region ?? 'us-east-1',
      credentials: config.credentials,
      forcePathStyle: config.forcePathStyle ?? true,
    };
  }

  /** Sign and execute any S3 command */
  async send(command: PutObjectCommand): Promise<void>;
  async send(command: GetObjectCommand): Promise<GetObjectOutput>;
  async send(command: DeleteObjectCommand): Promise<void>;
  async send(command: HeadBucketCommand): Promise<void>;
  async send(command: CreateBucketCommand): Promise<void>;
  async send(command: HeadObjectCommand): Promise<HeadObjectOutput>;
  async send(command: ListObjectsV2Command): Promise<ListObjectsV2Output>;
  async send(command: S3Command): Promise<unknown> {
    switch (command._type) {
      case 'PutObject':
        return this._putObject(command.input);
      case 'GetObject':
        return this._getObject(command.input);
      case 'DeleteObject':
        return this._deleteObject(command.input);
      case 'HeadBucket':
        return this._headBucket(command.input);
      case 'CreateBucket':
        return this._createBucket(command.input);
      case 'HeadObject':
        return this._headObject(command.input);
      case 'ListObjectsV2':
        return this._listObjectsV2(command.input);
      default: {
        // Type narrowing exhaustiveness — should never reach here
        const _exhaustive: never = command;
        throw new Error(`Unknown S3 command: ${(_exhaustive as S3Command)._type}`);
      }
    }
  }

  /** Build and return signed headers + url for a request */
  private _sign(
    method: string,
    url: URL,
    extraHeaders: Record<string, string>,
    bodyHash: string,
  ): { headers: Record<string, string>; amzDate: string } {
    const date = new Date();
    const { authorization, amzDate } = signRequest({
      method,
      url,
      headers: extraHeaders,
      bodyHash,
      accessKeyId: this.config.credentials.accessKeyId,
      secretAccessKey: this.config.credentials.secretAccessKey,
      region: this.config.region,
      service: 's3',
      date,
    });

    return {
      headers: {
        ...extraHeaders,
        host: url.host,
        'x-amz-date': amzDate,
        authorization,
      },
      amzDate,
    };
  }

  // ─── PutObject ──────────────────────────────────────────────────────────────

  private async _putObject(input: PutObjectInput): Promise<void> {
    const url = buildObjectUrl(this.config, input.Bucket, input.Key);
    const bodyBuf = await bodyToBuffer(input.Body);
    const bodyHash = sha256Hex(bodyBuf);

    const extraHeaders: Record<string, string> = {
      'content-type': input.ContentType ?? 'application/octet-stream',
      'content-length': String(bodyBuf.length),
      'x-amz-content-sha256': bodyHash,
    };

    // Add user metadata headers
    if (input.Metadata) {
      for (const [k, v] of Object.entries(input.Metadata)) {
        extraHeaders[`x-amz-meta-${k.toLowerCase()}`] = v;
      }
    }

    const { headers } = this._sign('PUT', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'PUT', headers, bodyBuf);
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      throwS3Error(resp.statusCode, resp.body, 'PutObject');
    }
  }

  // ─── GetObject ──────────────────────────────────────────────────────────────

  private async _getObject(input: GetObjectInput): Promise<GetObjectOutput> {
    const url = buildObjectUrl(this.config, input.Bucket, input.Key);
    const bodyHash = sha256Hex('');

    const extraHeaders: Record<string, string> = {
      'x-amz-content-sha256': bodyHash,
    };

    const { headers } = this._sign('GET', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'GET', headers, undefined, true);
    if (resp.statusCode < 200 || resp.statusCode >= 300) {
      // We need to buffer the error body
      const chunks: Buffer[] = [];
      for await (const chunk of resp.stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
      }
      throwS3Error(resp.statusCode, Buffer.concat(chunks), 'GetObject');
    }

    // Build a Readable that also has transformToString() (used in model-spec.ts)
    const stream = resp.stream as Readable & { transformToString(): Promise<string> };
    stream.transformToString = async (): Promise<string> => {
      const chunks: Buffer[] = [];
      for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
      }
      return Buffer.concat(chunks).toString('utf8');
    };

    // Parse metadata from response headers
    const metadata: Record<string, string> = {};
    for (const [k, v] of Object.entries(resp.headers)) {
      if (k.startsWith('x-amz-meta-')) {
        metadata[k.slice('x-amz-meta-'.length)] = v;
      }
    }

    const contentLength = resp.headers['content-length']
      ? parseInt(resp.headers['content-length'], 10)
      : undefined;

    const lastModified = resp.headers['last-modified']
      ? new Date(resp.headers['last-modified'])
      : undefined;

    return {
      Body: stream,
      ContentType: resp.headers['content-type'],
      ContentLength: contentLength,
      LastModified: lastModified,
      ETag: resp.headers['etag'],
      Metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
    };
  }

  // ─── DeleteObject ───────────────────────────────────────────────────────────

  private async _deleteObject(input: DeleteObjectInput): Promise<void> {
    const url = buildObjectUrl(this.config, input.Bucket, input.Key);
    const bodyHash = sha256Hex('');

    const extraHeaders: Record<string, string> = {
      'x-amz-content-sha256': bodyHash,
    };

    const { headers } = this._sign('DELETE', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'DELETE', headers);
    if (resp.statusCode >= 300 && resp.statusCode !== 204) {
      throwS3Error(resp.statusCode, resp.body, 'DeleteObject');
    }
  }

  // ─── HeadBucket ─────────────────────────────────────────────────────────────

  private async _headBucket(input: HeadBucketInput): Promise<void> {
    const url = buildObjectUrl(this.config, input.Bucket);
    const bodyHash = sha256Hex('');

    const extraHeaders: Record<string, string> = {
      'x-amz-content-sha256': bodyHash,
    };

    const { headers } = this._sign('HEAD', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'HEAD', headers);
    if (resp.statusCode === 404) {
      const err = new Error(`HeadBucket: NoSuchBucket — ${input.Bucket}`);
      (err as NodeJS.ErrnoException).code = 'NoSuchBucket';
      throw err;
    }
    if (resp.statusCode >= 300) {
      const err = new Error(`HeadBucket failed: HTTP ${resp.statusCode}`);
      (err as NodeJS.ErrnoException).code = String(resp.statusCode);
      throw err;
    }
  }

  // ─── CreateBucket ───────────────────────────────────────────────────────────

  private async _createBucket(input: CreateBucketInput): Promise<void> {
    const url = buildObjectUrl(this.config, input.Bucket);
    const bodyHash = sha256Hex('');

    const extraHeaders: Record<string, string> = {
      'content-length': '0',
      'x-amz-content-sha256': bodyHash,
    };

    const { headers } = this._sign('PUT', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'PUT', headers);
    if (resp.statusCode >= 300 && resp.statusCode !== 200 && resp.statusCode !== 204) {
      throwS3Error(resp.statusCode, resp.body, 'CreateBucket');
    }
  }

  // ─── HeadObject ─────────────────────────────────────────────────────────────

  private async _headObject(input: HeadObjectInput): Promise<HeadObjectOutput> {
    const url = buildObjectUrl(this.config, input.Bucket, input.Key);
    const bodyHash = sha256Hex('');

    const extraHeaders: Record<string, string> = {
      'x-amz-content-sha256': bodyHash,
    };

    const { headers } = this._sign('HEAD', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'HEAD', headers);
    if (resp.statusCode === 404) {
      const err = new Error(`HeadObject: NoSuchKey — ${input.Key}`);
      (err as NodeJS.ErrnoException).code = 'NoSuchKey';
      throw err;
    }
    if (resp.statusCode >= 300) {
      const err = new Error(`HeadObject failed: HTTP ${resp.statusCode}`);
      (err as NodeJS.ErrnoException).code = String(resp.statusCode);
      throw err;
    }

    const metadata: Record<string, string> = {};
    for (const [k, v] of Object.entries(resp.headers)) {
      if (k.startsWith('x-amz-meta-')) {
        metadata[k.slice('x-amz-meta-'.length)] = v;
      }
    }

    const contentLength = resp.headers['content-length']
      ? parseInt(resp.headers['content-length'], 10)
      : undefined;

    const lastModified = resp.headers['last-modified']
      ? new Date(resp.headers['last-modified'])
      : undefined;

    return {
      ContentType: resp.headers['content-type'],
      ContentLength: contentLength,
      LastModified: lastModified,
      ETag: resp.headers['etag'],
      Metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
    };
  }

  // ─── ListObjectsV2 ──────────────────────────────────────────────────────────

  private async _listObjectsV2(input: ListObjectsV2Input): Promise<ListObjectsV2Output> {
    const url = buildObjectUrl(this.config, input.Bucket);

    // Build query params
    url.searchParams.set('list-type', '2');
    if (input.Prefix !== undefined) url.searchParams.set('prefix', input.Prefix);
    if (input.Delimiter !== undefined) url.searchParams.set('delimiter', input.Delimiter);
    if (input.MaxKeys !== undefined) url.searchParams.set('max-keys', String(input.MaxKeys));
    if (input.ContinuationToken !== undefined) {
      url.searchParams.set('continuation-token', input.ContinuationToken);
    }

    const bodyHash = sha256Hex('');
    const extraHeaders: Record<string, string> = {
      'x-amz-content-sha256': bodyHash,
    };

    const { headers } = this._sign('GET', url, extraHeaders, bodyHash);

    const resp = await makeRequest(url, 'GET', headers);
    if (resp.statusCode >= 300) {
      throwS3Error(resp.statusCode, resp.body, 'ListObjectsV2');
    }

    const xmlText = resp.body.toString('utf8');
    return parseListObjectsV2(xmlText);
  }

  // ─── Presigned URL generation ────────────────────────────────────────────────

  /**
   * Generate a presigned URL for a GetObject request.
   * Signs via query params (not Authorization header).
   */
  presignGetObject(bucket: string, key: string, expiresIn: number): string {
    const url = buildObjectUrl(this.config, bucket, key);
    const date = new Date();
    const amzDate = formatDateTime(date);
    const dateOnly = formatDate(date);

    const { accessKeyId, secretAccessKey } = this.config.credentials;
    const { region } = this.config;
    const service = 's3';

    const credentialScope = `${dateOnly}/${region}/${service}/aws4_request`;
    const credential = `${accessKeyId}/${credentialScope}`;

    // Add required presigned URL query params
    url.searchParams.set('X-Amz-Algorithm', 'AWS4-HMAC-SHA256');
    url.searchParams.set('X-Amz-Credential', credential);
    url.searchParams.set('X-Amz-Date', amzDate);
    url.searchParams.set('X-Amz-Expires', String(expiresIn));
    url.searchParams.set('X-Amz-SignedHeaders', 'host');

    // Canonical request for presigned URL (body hash is UNSIGNED-PAYLOAD for presigned)
    const sortedParams = Array.from(url.searchParams.entries())
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');

    const canonicalRequest = [
      'GET',
      url.pathname,
      sortedParams,
      `host:${url.host}\n`,
      'host',
      'UNSIGNED-PAYLOAD',
    ].join('\n');

    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      sha256Hex(canonicalRequest),
    ].join('\n');

    const signingKey = getSigningKey(secretAccessKey, dateOnly, region, service);
    const signature = hexEncode(hmacSha256(signingKey, stringToSign));

    url.searchParams.set('X-Amz-Signature', signature);

    return url.toString();
  }
}

// ─── getSignedUrl — AWS SDK v3 compatible drop-in ────────────────────────────

/**
 * Generate a presigned URL for a GetObjectCommand.
 * Drop-in replacement for @aws-sdk/s3-request-presigner's getSignedUrl.
 */
export async function getSignedUrl(
  client: PetraS3Client,
  command: GetObjectCommand,
  options?: { expiresIn?: number },
): Promise<string> {
  const expiresIn = options?.expiresIn ?? 3600;
  return client.presignGetObject(command.input.Bucket, command.input.Key, expiresIn);
}
