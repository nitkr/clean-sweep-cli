<?php
/**
 * Plugin Name: Good Plugin
 * Version: 1.0.0
 */

function good_plugin_init() {
    // Some legitimate code
    add_action('wp_footer', function() {
        echo '<p>Hello World</p>';
    });
}
add_action('plugins_loaded', 'good_plugin_init');
