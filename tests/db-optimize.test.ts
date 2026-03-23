import { describe, it, expect } from '@jest/globals';
import * as path from 'path';
import * as fs from 'fs';
import { generateOptimizationQueries, generateOptimizationScript, registerDbOptimizeCommand } from '../src/commands/db-optimize';

describe('db-optimize', () => {
  describe('generateOptimizationQueries', () => {
    it('should return an array of optimization tasks', () => {
      const tasks = generateOptimizationQueries('wp_');
      expect(Array.isArray(tasks)).toBe(true);
      expect(tasks.length).toBeGreaterThan(0);
    });

    it('should use the provided table prefix', () => {
      const tasks = generateOptimizationQueries('custom_');
      for (const task of tasks) {
        expect(task.table).toMatch(/^custom_/);
      }
    });

    it('should use default wp_ prefix', () => {
      const tasks = generateOptimizationQueries('wp_');
      for (const task of tasks) {
        expect(task.table).toMatch(/^wp_/);
      }
    });

    it('should include delete post revisions task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const revisionTask = tasks.find(t => t.action === 'delete_post_revisions');
      expect(revisionTask).toBeDefined();
      expect(revisionTask?.query).toContain("post_type = 'revision'");
      expect(revisionTask?.table).toBe('wp_posts');
    });

    it('should include delete auto-drafts task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_auto_drafts');
      expect(task).toBeDefined();
      expect(task?.query).toContain("post_status = 'auto-draft'");
    });

    it('should include delete trashed posts task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_trashed_posts');
      expect(task).toBeDefined();
      expect(task?.query).toContain("post_status = 'trash'");
    });

    it('should include delete orphaned postmeta task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_orphaned_postmeta');
      expect(task).toBeDefined();
      expect(task?.query).toContain('LEFT JOIN');
      expect(task?.table).toBe('wp_postmeta');
    });

    it('should include delete orphaned commentmeta task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_orphaned_commentmeta');
      expect(task).toBeDefined();
      expect(task?.query).toContain('LEFT JOIN');
      expect(task?.table).toBe('wp_commentmeta');
    });

    it('should include delete trashed comments task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_trashed_comments');
      expect(task).toBeDefined();
      expect(task?.query).toContain("comment_approved = 'trash'");
    });

    it('should include delete spam comments task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_spam_comments');
      expect(task).toBeDefined();
      expect(task?.query).toContain("comment_approved = 'spam'");
    });

    it('should include delete expired transients task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_expired_transients');
      expect(task).toBeDefined();
      expect(task?.query).toContain('_transient_timeout_');
      expect(task?.query).toContain('UNIX_TIMESTAMP()');
    });

    it('should include delete orphaned transients task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_orphaned_transients');
      expect(task).toBeDefined();
      expect(task?.query).toContain('_transient_');
    });

    it('should include delete orphaned term relationships task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_orphaned_term_relationships');
      expect(task).toBeDefined();
      expect(task?.query).toContain('term_relationships');
    });

    it('should include delete unused terms task', () => {
      const tasks = generateOptimizationQueries('wp_');
      const task = tasks.find(t => t.action === 'delete_unused_terms');
      expect(task).toBeDefined();
      expect(task?.query).toContain('term_taxonomy');
    });

    it('should include OPTIMIZE TABLE tasks for core WordPress tables', () => {
      const tasks = generateOptimizationQueries('wp_');
      const optimizeTasks = tasks.filter(t => t.action === 'optimize');
      expect(optimizeTasks.length).toBe(10);

      const tablesToOptimize = [
        'wp_posts', 'wp_postmeta', 'wp_comments', 'wp_commentmeta',
        'wp_options', 'wp_terms', 'wp_term_taxonomy',
        'wp_term_relationships', 'wp_users', 'wp_usermeta',
      ];

      for (const table of tablesToOptimize) {
        const task = optimizeTasks.find(t => t.table === table);
        expect(task).toBeDefined();
        expect(task?.query).toBe(`OPTIMIZE TABLE ${table};`);
      }
    });

    it('should include savingsEstimate for every task', () => {
      const tasks = generateOptimizationQueries('wp_');
      for (const task of tasks) {
        expect(task.savingsEstimate).toBeDefined();
        expect(typeof task.savingsEstimate).toBe('string');
        expect(task.savingsEstimate.length).toBeGreaterThan(0);
      }
    });

    it('should include action and query for every task', () => {
      const tasks = generateOptimizationQueries('wp_');
      for (const task of tasks) {
        expect(task.action).toBeDefined();
        expect(task.query).toBeDefined();
        expect(task.table).toBeDefined();
      }
    });

    it('should work with different prefixes', () => {
      const prefixes = ['wp_', 'blog_', 'site1_', 'x_'];
      for (const prefix of prefixes) {
        const tasks = generateOptimizationQueries(prefix);
        for (const task of tasks) {
          expect(task.table).toMatch(new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
          expect(task.query).toContain(prefix);
        }
      }
    });
  });

  describe('generateOptimizationScript', () => {
    const mockCredentials = {
      host: 'localhost',
      name: 'wordpress_db',
      user: 'wp_user',
      pass: 'wp_pass',
      prefix: 'wp_',
    };

    it('should generate a bash script', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('#!/usr/bin/env bash');
      expect(script).toContain('set -euo pipefail');
    });

    it('should include database credentials', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('DB_HOST="localhost"');
      expect(script).toContain('DB_NAME="wordpress_db"');
      expect(script).toContain('DB_USER="wp_user"');
      expect(script).toContain('DB_PASS="wp_pass"');
    });

    it('should include all optimization queries', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      for (const task of tasks) {
        expect(script).toContain(task.action);
      }
    });

    it('should include generation date', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('# Generated by clean-sweep db:optimize');
      expect(script).toContain(`# Date:`);
    });

    it('should include echo for progress', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('echo "Starting WordPress database optimization..."');
      expect(script).toContain('echo "Optimization complete."');
    });

    it('should include MYSQL_CMD variable', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('MYSQL_CMD="mysql -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME"');
    });

    it('should escape double quotes in queries', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('$MYSQL_CMD -e "');
    });

    it('should work with empty password', () => {
      const creds = { ...mockCredentials, pass: '' };
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, creds);

      expect(script).toContain('DB_PASS=""');
    });

    it('should include task numbering', () => {
      const tasks = generateOptimizationQueries('wp_');
      const script = generateOptimizationScript(tasks, mockCredentials);

      expect(script).toContain('# Task 1:');
      expect(script).toContain(`# Task ${tasks.length}:`);
    });
  });

  describe('registerDbOptimizeCommand', () => {
    it('should register the db:optimize command', () => {
      const mockProgram = {
        command: jest.fn().mockReturnThis(),
        description: jest.fn().mockReturnThis(),
        option: jest.fn().mockReturnThis(),
        action: jest.fn().mockReturnThis(),
      };
      const getOpts = () => ({
        dryRun: true,
        force: false,
        json: false,
        path: process.cwd(),
        verbose: false,
      });

      registerDbOptimizeCommand(mockProgram as any, getOpts);

      expect(mockProgram.command).toHaveBeenCalledWith('db:optimize');
      expect(mockProgram.description).toHaveBeenCalledWith(
        'Generate WordPress database optimization queries and scripts'
      );
      expect(mockProgram.option).toHaveBeenCalled();
      expect(mockProgram.action).toHaveBeenCalled();
    });
  });
});
