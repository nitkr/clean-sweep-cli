import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  classifySeverity,
  classifyCategory,
  groupByType,
  groupBySeverity,
  groupByCategory,
  calculateRiskScore,
  riskLevelFromScore,
  generateSummary,
} from '../src/commands/summary';
import { Threat } from '../src/malware-scanner';

describe('Summary Module', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'summary-test-'));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('classifySeverity', () => {
    it('should classify php_eval as high', () => {
      expect(classifySeverity('php_eval')).toBe('high');
    });

    it('should classify php_shell_exec as high', () => {
      expect(classifySeverity('php_shell_exec')).toBe('high');
    });

    it('should classify php_base64_decode as medium', () => {
      expect(classifySeverity('php_base64_decode')).toBe('medium');
    });

    it('should classify js_eval_dynamic as high', () => {
      expect(classifySeverity('js_eval_dynamic')).toBe('high');
    });

    it('should classify js_settimeout_dynamic as medium', () => {
      expect(classifySeverity('js_settimeout_dynamic')).toBe('medium');
    });

    it('should classify base64_large as low', () => {
      expect(classifySeverity('base64_large')).toBe('low');
    });

    it('should classify unknown types as low', () => {
      expect(classifySeverity('unknown_type')).toBe('low');
    });
  });

  describe('classifyCategory', () => {
    it('should classify php_ types as php-code', () => {
      expect(classifyCategory('php_eval')).toBe('php-code');
      expect(classifyCategory('php_system')).toBe('php-code');
    });

    it('should classify js_ types as js-code', () => {
      expect(classifyCategory('js_eval_dynamic')).toBe('js-code');
      expect(classifyCategory('js_document_write')).toBe('js-code');
    });

    it('should classify encoded content types as encoded-content', () => {
      expect(classifyCategory('base64_large')).toBe('encoded-content');
      expect(classifyCategory('char_encoding')).toBe('encoded-content');
      expect(classifyCategory('hex_escape')).toBe('encoded-content');
      expect(classifyCategory('url_encoding')).toBe('encoded-content');
      expect(classifyCategory('nested_encoding')).toBe('encoded-content');
      expect(classifyCategory('mixed_case_base64')).toBe('encoded-content');
    });

    it('should classify suspicious file types as suspicious-file', () => {
      expect(classifyCategory('suspicious_php_extension')).toBe('suspicious-file');
      expect(classifyCategory('suspicious_php_filename')).toBe('suspicious-file');
      expect(classifyCategory('alternative_php')).toBe('suspicious-file');
      expect(classifyCategory('path_traversal')).toBe('suspicious-file');
    });

    it('should classify unknown types as other', () => {
      expect(classifyCategory('something_else')).toBe('other');
    });
  });

  describe('groupByType', () => {
    it('should group threats by type and sort by count descending', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'b.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'c.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'd.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
        { file: 'e.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
        { file: 'f.php', type: 'php_system', line: null, signature: 'system(' },
      ];

      const result = groupByType(threats);
      expect(result).toEqual([
        { type: 'php_eval', count: 3 },
        { type: 'php_base64_decode', count: 2 },
        { type: 'php_system', count: 1 },
      ]);
    });

    it('should return empty array for no threats', () => {
      expect(groupByType([])).toEqual([]);
    });
  });

  describe('groupBySeverity', () => {
    it('should group threats by severity in order high, medium, low', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'b.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'c.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
        { file: 'd.php', type: 'base64_large', line: null, signature: 'aaa...' },
      ];

      const result = groupBySeverity(threats);
      expect(result).toEqual([
        { severity: 'high', count: 2 },
        { severity: 'medium', count: 1 },
        { severity: 'low', count: 1 },
      ]);
    });

    it('should only include present severity levels', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
      ];

      const result = groupBySeverity(threats);
      expect(result).toEqual([{ severity: 'high', count: 1 }]);
    });

    it('should return empty array for no threats', () => {
      expect(groupBySeverity([])).toEqual([]);
    });
  });

  describe('groupByCategory', () => {
    it('should group threats by category and sort by count descending', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'b.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'c.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'd.js', type: 'js_eval_dynamic', line: null, signature: "eval('" },
        { file: 'e.js', type: 'js_eval_dynamic', line: null, signature: "eval('" },
        { file: 'f.php', type: 'base64_large', line: null, signature: 'aaa...' },
      ];

      const result = groupByCategory(threats);
      expect(result).toEqual([
        { category: 'php-code', count: 3 },
        { category: 'js-code', count: 2 },
        { category: 'encoded-content', count: 1 },
      ]);
    });

    it('should return empty array for no threats', () => {
      expect(groupByCategory([])).toEqual([]);
    });
  });

  describe('calculateRiskScore', () => {
    it('should return 0 for no threats', () => {
      expect(calculateRiskScore([])).toBe(0);
    });

    it('should score high threats at 10 points each', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'b.php', type: 'php_eval', line: null, signature: 'eval(' },
      ];
      expect(calculateRiskScore(threats)).toBe(20);
    });

    it('should score medium threats at 5 points each', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
        { file: 'b.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
      ];
      expect(calculateRiskScore(threats)).toBe(10);
    });

    it('should score low threats at 1 point each', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'base64_large', line: null, signature: 'aaa...' },
        { file: 'b.php', type: 'base64_large', line: null, signature: 'aaa...' },
      ];
      expect(calculateRiskScore(threats)).toBe(2);
    });

    it('should cap score at 100', () => {
      const threats: Threat[] = Array.from({ length: 20 }, (_, i) => ({
        file: `file${i}.php`,
        type: 'php_eval',
        line: null,
        signature: 'eval(',
      }));
      expect(calculateRiskScore(threats)).toBe(100);
    });

    it('should combine severities correctly', () => {
      const threats: Threat[] = [
        { file: 'a.php', type: 'php_eval', line: null, signature: 'eval(' },
        { file: 'b.php', type: 'php_base64_decode', line: null, signature: 'base64_decode(' },
        { file: 'c.php', type: 'base64_large', line: null, signature: 'aaa...' },
      ];
      expect(calculateRiskScore(threats)).toBe(16);
    });
  });

  describe('riskLevelFromScore', () => {
    it('should return none for 0', () => {
      expect(riskLevelFromScore(0)).toBe('none');
    });

    it('should return low for scores 1-14', () => {
      expect(riskLevelFromScore(1)).toBe('low');
      expect(riskLevelFromScore(14)).toBe('low');
    });

    it('should return medium for scores 15-39', () => {
      expect(riskLevelFromScore(15)).toBe('medium');
      expect(riskLevelFromScore(39)).toBe('medium');
    });

    it('should return high for scores 40-69', () => {
      expect(riskLevelFromScore(40)).toBe('high');
      expect(riskLevelFromScore(69)).toBe('high');
    });

    it('should return critical for scores 70-100', () => {
      expect(riskLevelFromScore(70)).toBe('critical');
      expect(riskLevelFromScore(100)).toBe('critical');
    });
  });

  describe('generateSummary', () => {
    it('should return empty summary for clean directory', async () => {
      const cleanDir = path.join(tempDir, 'clean');
      fs.mkdirSync(cleanDir, { recursive: true });
      fs.writeFileSync(path.join(cleanDir, 'index.php'), '<?php echo "hello"; ?>');

      const result = await generateSummary(cleanDir);

      expect(result.totalThreats).toBe(0);
      expect(result.riskScore).toBe(0);
      expect(result.riskLevel).toBe('none');
      expect(result.byType).toEqual([]);
      expect(result.bySeverity).toEqual([]);
      expect(result.byCategory).toEqual([]);
      expect(result.affectedFiles).toBe(0);
    });

    it('should detect threats in PHP files', async () => {
      const targetDir = path.join(tempDir, 'malicious');
      fs.mkdirSync(targetDir, { recursive: true });
      fs.writeFileSync(path.join(targetDir, 'evil.php'), '<?php eval($_GET["cmd"]); ?>');
      fs.writeFileSync(path.join(targetDir, 'shell.php'), '<?php shell_exec("ls"); ?>');

      const result = await generateSummary(targetDir);

      expect(result.totalThreats).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(0);
      expect(result.byType.length).toBeGreaterThan(0);
      expect(result.affectedFiles).toBe(2);
    });

    it('should skip non-php/js files', async () => {
      const targetDir = path.join(tempDir, 'mixed');
      fs.mkdirSync(targetDir, { recursive: true });
      fs.writeFileSync(path.join(targetDir, 'readme.txt'), 'eval() system() shell_exec()');
      fs.writeFileSync(path.join(targetDir, 'script.js'), 'console.log("safe");');

      const result = await generateSummary(targetDir);

      expect(result.totalThreats).toBe(0);
    });

    it('should detect threats in JS files', async () => {
      const targetDir = path.join(tempDir, 'js-threats');
      fs.mkdirSync(targetDir, { recursive: true });
      fs.writeFileSync(path.join(targetDir, 'mal.js'), "eval('alert(1)');");

      const result = await generateSummary(targetDir);

      expect(result.totalThreats).toBeGreaterThan(0);
      expect(result.byCategory.some(c => c.category === 'js-code')).toBe(true);
    });

    it('should ignore node_modules, dist, and .git directories', async () => {
      const targetDir = path.join(tempDir, 'ignored-dirs');
      fs.mkdirSync(path.join(targetDir, 'node_modules'), { recursive: true });
      fs.mkdirSync(path.join(targetDir, 'dist'), { recursive: true });
      fs.mkdirSync(path.join(targetDir, '.git'), { recursive: true });
      fs.writeFileSync(
        path.join(targetDir, 'node_modules', 'evil.php'),
        '<?php eval($cmd); ?>'
      );
      fs.writeFileSync(
        path.join(targetDir, 'dist', 'evil.php'),
        '<?php eval($cmd); ?>'
      );
      fs.writeFileSync(
        path.join(targetDir, '.git', 'evil.php'),
        '<?php eval($cmd); ?>'
      );
      fs.writeFileSync(
        path.join(targetDir, 'safe.php'),
        '<?php echo "hello"; ?>'
      );

      const result = await generateSummary(targetDir);

      expect(result.totalThreats).toBe(0);
    });

    it('should correctly count affected files', async () => {
      const targetDir = path.join(tempDir, 'multi-file');
      fs.mkdirSync(targetDir, { recursive: true });
      fs.writeFileSync(path.join(targetDir, 'a.php'), '<?php eval($x); ?>');
      fs.writeFileSync(path.join(targetDir, 'b.php'), '<?php eval($x); ?>');
      fs.writeFileSync(path.join(targetDir, 'c.php'), '<?php echo "safe"; ?>');

      const result = await generateSummary(targetDir);

      expect(result.affectedFiles).toBe(2);
    });
  });
});
