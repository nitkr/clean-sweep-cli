import * as fs from 'fs';
import * as path from 'path';
import winston from 'winston';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_DIR = 'clean-sweep-cli/logs';
const LOG_FILE = 'clean-sweep.log';

function ensureLogDir(): void {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function createFileTransport(): winston.transport {
  ensureLogDir();
  return new winston.transports.File({
    filename: path.join(LOG_DIR, LOG_FILE),
    level: 'debug',
    maxsize: 10 * 1024 * 1024,
    maxFiles: 5,
  });
}

export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  setLevel(level: LogLevel): void;
}

let loggerInstance: winston.Logger | null = null;
let currentLevel: LogLevel = 'info';

function getTimestamp(): string {
  return new Date().toISOString();
}

function formatMessage(level: string, message: string, meta?: Record<string, unknown>): string {
  const timestamp = getTimestamp();
  const metaStr = meta ? ` ${JSON.stringify(meta)}` : '';
  return `[${timestamp}] [${level.toUpperCase()}] ${message}${metaStr}`;
}

export function createLogger(level: LogLevel = 'info'): Logger {
  currentLevel = level;
  ensureLogDir();

  loggerInstance = winston.createLogger({
    level,
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.printf(({ level, message, timestamp }) => {
            return `[${timestamp}] [${level}] ${message}`;
          })
        ),
      }),
      createFileTransport(),
    ],
  });

  return {
    debug(message: string, meta?: Record<string, unknown>): void {
      loggerInstance?.debug(formatMessage('debug', message, meta));
    },
    info(message: string, meta?: Record<string, unknown>): void {
      loggerInstance?.info(formatMessage('info', message, meta));
    },
    warn(message: string, meta?: Record<string, unknown>): void {
      loggerInstance?.warn(formatMessage('warn', message, meta));
    },
    error(message: string, meta?: Record<string, unknown>): void {
      loggerInstance?.error(formatMessage('error', message, meta));
    },
    setLevel(level: LogLevel): void {
      currentLevel = level;
      if (loggerInstance) {
        loggerInstance.level = level;
      }
    },
  };
}

export function getLogger(): Logger {
  if (!loggerInstance) {
    return createLogger(currentLevel);
  }
  const instance = loggerInstance;
  return {
    debug(message: string, meta?: Record<string, unknown>): void {
      instance.debug(formatMessage('debug', message, meta));
    },
    info(message: string, meta?: Record<string, unknown>): void {
      instance.info(formatMessage('info', message, meta));
    },
    warn(message: string, meta?: Record<string, unknown>): void {
      instance.warn(formatMessage('warn', message, meta));
    },
    error(message: string, meta?: Record<string, unknown>): void {
      instance.error(formatMessage('error', message, meta));
    },
    setLevel(level: LogLevel): void {
      currentLevel = level;
      instance.level = level;
    },
  };
}

export interface ReportData {
  timestamp: string;
  scanPath: string;
  results: Record<string, unknown>;
  suggestions: string[];
}

export function generateReport(
  scanPath: string,
  results: Record<string, unknown>,
  suggestions: string[]
): ReportData {
  return {
    timestamp: getTimestamp(),
    scanPath,
    results,
    suggestions,
  };
}

export function saveReport(report: ReportData, filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf-8');
}

export function getDefaultReportPath(scanPath: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const safePath = scanPath.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 50);
  return path.join('clean-sweep-cli', 'reports', `scan-${safePath}-${timestamp}.json`);
}
