import path from "node:path";
import { createLogger, createHttpLogger } from "../sovereign/petra-logger.js";
import { readConfigFile } from "../config-file.js";
import { resolveDefaultLogsDir, resolveHomeAwarePath } from "../home-paths.js";

function resolveServerLogDir(): string {
  const envOverride = process.env.PAPERCLIP_LOG_DIR?.trim();
  if (envOverride) return resolveHomeAwarePath(envOverride);

  const fileLogDir = readConfigFile()?.logging.logDir?.trim();
  if (fileLogDir) return resolveHomeAwarePath(fileLogDir);

  return resolveDefaultLogsDir();
}

const logDir = resolveServerLogDir();

export const logger = createLogger({
  level: "debug",
  logDir,
  logFile: "server.log",
});

export const httpLogger = createHttpLogger(logger);
