import { Readable } from "node:stream";
import type { StorageProvider, GetObjectResult, HeadObjectResult } from "./types.js";
import { notFound, unprocessable } from "../errors.js";
import {
  PetraS3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
} from "../sovereign/petra-s3.js";

interface S3ProviderConfig {
  bucket: string;
  region: string;
  endpoint?: string;
  prefix?: string;
  forcePathStyle?: boolean;
}

function normalizePrefix(prefix: string | undefined): string {
  if (!prefix) return "";
  return prefix
    .trim()
    .replace(/^\/+/, "")
    .replace(/\/+$/, "");
}

function buildKey(prefix: string, objectKey: string): string {
  if (!prefix) return objectKey;
  return `${prefix}/${objectKey}`;
}

function toDate(value: Date | undefined): Date | undefined {
  return value instanceof Date ? value : undefined;
}

export function createS3StorageProvider(config: S3ProviderConfig): StorageProvider {
  const bucket = config.bucket.trim();
  const region = config.region.trim();
  if (!bucket) throw unprocessable("S3 storage bucket is required");
  if (!region) throw unprocessable("S3 storage region is required");

  const prefix = normalizePrefix(config.prefix);

  // Build a valid endpoint — PetraS3Client requires a full URL
  let endpoint = config.endpoint ?? `https://s3.${region}.amazonaws.com`;
  if (!endpoint.startsWith('http://') && !endpoint.startsWith('https://')) {
    endpoint = `https://${endpoint}`;
  }

  const client = new PetraS3Client({
    endpoint,
    region,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? process.env.S3_ACCESS_KEY_ID ?? "",
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? process.env.S3_SECRET_ACCESS_KEY ?? "",
    },
    forcePathStyle: Boolean(config.forcePathStyle),
  });

  return {
    id: "s3",

    async putObject(input) {
      const key = buildKey(prefix, input.objectKey);
      await client.send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: input.body,
          ContentType: input.contentType,
        }),
      );
    },

    async getObject(input): Promise<GetObjectResult> {
      const key = buildKey(prefix, input.objectKey);
      try {
        const output = await client.send(
          new GetObjectCommand({
            Bucket: bucket,
            Key: key,
          }),
        );

        // output.Body is already a Readable from petra-s3
        const stream = output.Body as Readable;

        return {
          stream,
          contentType: output.ContentType,
          contentLength: output.ContentLength,
          etag: output.ETag,
          lastModified: toDate(output.LastModified),
        };
      } catch (err) {
        const code = (err as { code?: string }).code;
        if (code === "NoSuchKey" || code === "NotFound" || code === "404") throw notFound("Object not found");
        throw err;
      }
    },

    async headObject(input): Promise<HeadObjectResult> {
      const key = buildKey(prefix, input.objectKey);
      try {
        const output = await client.send(
          new HeadObjectCommand({
            Bucket: bucket,
            Key: key,
          }),
        );

        return {
          exists: true,
          contentType: output.ContentType,
          contentLength: output.ContentLength,
          etag: output.ETag,
          lastModified: toDate(output.LastModified),
        };
      } catch (err) {
        const code = (err as { code?: string }).code;
        if (code === "NoSuchKey" || code === "NotFound" || code === "404") return { exists: false };
        throw err;
      }
    },

    async deleteObject(input): Promise<void> {
      const key = buildKey(prefix, input.objectKey);
      await client.send(
        new DeleteObjectCommand({
          Bucket: bucket,
          Key: key,
        }),
      );
    },
  };
}
