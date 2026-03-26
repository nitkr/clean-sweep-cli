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

export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
  setLevel(level: LogLevel): void;
  setSilent(silent: boolean): void;
}

interface LoggerInstance {
  logger: winston.Logger;
  consoleTransport: winston.transport;
  fileTransport: winston.transport | null;
  fileLoggingEnabled: boolean;
}

let loggerState: LoggerInstance | null = null;
let currentLevel: LogLevel = 'info';

function getTimestamp(): string {
  return new Date().toISOString();
}

function createHumanFormat() {
  return winston.format.printf(({ message }) => {
    return `${message}`;
  });
}

function createFileFormat() {
  return winston.format((info) => {
    const output = {
      timestamp: info.timestamp,
      level: info.level,
      message: info.message,
      [Symbol.for('meta')]: info.meta,
    };
    if (info.meta && Object.keys(info.meta).length > 0) {
      (output as Record<string, unknown>).meta = info.meta;
    }
    return output;
  });
}

function buildLogger(level: LogLevel): LoggerInstance {
  const consoleTransport = new winston.transports.Console({
    silent: true,
    format: createHumanFormat(),
  });

  const fileFormat = winston.format.combine(
    winston.format.timestamp(),
    createFileFormat()()
  );

  const fileTransport = new winston.transports.File({
    filename: path.join(LOG_DIR, LOG_FILE),
    level: 'debug',
    maxsize: 10 * 1024 * 1024,
    maxFiles: 5,
    format: fileFormat,
    silent: true,
  });

  const logger = winston.createLogger({
    level,
    transports: [consoleTransport, fileTransport],
  });

  return { logger, consoleTransport, fileTransport, fileLoggingEnabled: false };
}

export function createLogger(level: LogLevel = 'info'): Logger {
  currentLevel = level;
  ensureLogDir();
  loggerState = buildLogger(level);

  return {
    debug(message: string, meta?: Record<string, unknown>): void {
      loggerState?.logger.debug(message, meta as Record<string, unknown>);
    },
    info(message: string, meta?: Record<string, unknown>): void {
      loggerState?.logger.info(message, meta as Record<string, unknown>);
    },
    warn(message: string, meta?: Record<string, unknown>): void {
      loggerState?.logger.warn(message, meta as Record<string, unknown>);
    },
    error(message: string, meta?: Record<string, unknown>): void {
      loggerState?.logger.error(message, meta as Record<string, unknown>);
    },
    setLevel(level: LogLevel): void {
      currentLevel = level;
      if (loggerState) {
        loggerState.logger.level = level;
      }
    },
    setSilent(silent: boolean): void {
      if (loggerState) {
        loggerState.consoleTransport.silent = silent;
      }
    },
  };
}

export function enableFileLogging(): void {
  if (loggerState && loggerState.fileTransport) {
    loggerState.fileTransport.silent = false;
    loggerState.fileLoggingEnabled = true;
  }
}

export function isFileLoggingEnabled(): boolean {
  return loggerState?.fileLoggingEnabled ?? false;
}

export function getLogger(): Logger {
  if (!loggerState) {
    return createLogger(currentLevel);
  }
  const { logger, consoleTransport } = loggerState;
  return {
    debug(message: string, meta?: Record<string, unknown>): void {
      logger.debug(message, meta as Record<string, unknown>);
    },
    info(message: string, meta?: Record<string, unknown>): void {
      logger.info(message, meta as Record<string, unknown>);
    },
    warn(message: string, meta?: Record<string, unknown>): void {
      logger.warn(message, meta as Record<string, unknown>);
    },
    error(message: string, meta?: Record<string, unknown>): void {
      logger.error(message, meta as Record<string, unknown>);
    },
    setLevel(level: LogLevel): void {
      currentLevel = level;
      logger.level = level;
    },
    setSilent(silent: boolean): void {
      consoleTransport.silent = silent;
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