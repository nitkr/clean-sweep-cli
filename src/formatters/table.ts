import Table from 'cli-table3';

export interface TableConfig {
  head: string[];
  rows: string[][];
  style: {
    head: string[];
    border: string[];
  };
}

export const tableOptions: TableConfig = {
  head: [],
  rows: [],
  style: {
    head: [],
    border: [],
  },
};

export function createThreatTable() {
  return new Table({
    head: ['File', 'Type', 'Severity'],
    chars: {
      top: '─',
      'top-mid': '┬',
      'top-left': '┌',
      'top-right': '┐',
      bottom: '─',
      'bottom-mid': '┴',
      'bottom-left': '└',
      'bottom-right': '┘',
      left: '│',
      'left-mid': '├',
      right: '│',
      'right-mid': '┤',
      mid: '─',
      'mid-mid': '┼',
    },
    style: {
      head: [],
      border: [],
    },
  });
}

export function createVulnerabilityTable() {
  return new Table({
    head: ['Component', 'Version', 'Vulnerability', 'CVE', 'Severity', 'Recommendation'],
    chars: {
      top: '─',
      'top-mid': '┬',
      'top-left': '┌',
      'top-right': '┐',
      bottom: '─',
      'bottom-mid': '┴',
      'bottom-left': '└',
      'bottom-right': '┘',
      left: '│',
      'left-mid': '├',
      right: '│',
      'right-mid': '┤',
      mid: '─',
      'mid-mid': '┼',
    },
    style: {
      head: [],
      border: [],
    },
  });
}
