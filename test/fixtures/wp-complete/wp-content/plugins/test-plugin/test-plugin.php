<?php
/**
 * Plugin Name: Test Plugin
 * Plugin URI: https://example.com/test-plugin
 * Description: A test plugin for clean-sweep-cli testing
 * Version: 2.1.0
 * Author: Test Author
 * License: GPL v2 or later
 */

function test_plugin_init() {
    register_activation_hook( __FILE__, function() {
        flush_rewrite_rules();
    });
}
add_action( 'plugins_loaded', 'test_plugin_init' );