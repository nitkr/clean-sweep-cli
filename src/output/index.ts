export { icons } from './icons';
export { severityColor, severityIcon } from './colors';
export { createTable, createVulnerabilityTable, createThreatTable } from './table';
export { outputJson, outputErrorJson } from './json';
export { formatScanOutput } from './formatter';

import * as formatter from './formatter';
import * as table from './table';
import * as colors from './colors';
import * as icons from './icons';
import * as json from './json';

export default {
  icons,
  colors,
  table,
  json,
  formatter,
};
