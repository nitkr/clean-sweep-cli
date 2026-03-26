import Table from 'cli-table3';

export interface TableOptions {
  head: string[];
  colWidths?: number[];
  style?: {
    head?: string[];
    border?: string[];
  };
}

export function createTable(options: TableOptions): Table {
  return new Table({
    head: options.head,
    colWidths: options.colWidths,
    style: {
      head: options.style?.head || ['cyan'],
      border: options.style?.border || ['gray'],
    },
  }) as unknown as Table;
}

export function createVulnerabilityTable(): Table {
  return createTable({
    head: ['Component', 'Installed', 'Vulnerability', 'CVE', 'Severity', 'Recommendation'],
    colWidths: [20, 12, 40, 18, 12, 20],
  });
}

export function truncatePath(path: string, maxLength: number = 80): string {
  if (path.length <= maxLength) {
    return path;
  }
  const startLength = Math.floor((maxLength - 3) / 2);
  const endLength = maxLength - 3 - startLength;
  return path.slice(0, startLength) + '...' + path.slice(-endLength);
}

export function createThreatTable(): Table {
  return createTable({
    head: ['File', 'Type', 'Severity'],
    colWidths: [120, 30, 15],
  });
}
