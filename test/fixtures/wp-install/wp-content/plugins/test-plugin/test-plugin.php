<?php
/**
 * Plugin Name: Test Plugin
 * Plugin URI: https://example.com/test-plugin
 * Description: A test plugin for malware scanner validation
 * Version: 1.0.0
 * Author: Test Author
 * License: GPL2
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

function test_plugin_init() {
    load_plugin_textdomain( 'test-plugin', false, dirname( plugin_basename( __FILE__ ) ) );
}

add_action( 'plugins_loaded', 'test_plugin_init' );

function test_plugin_shortcode( $atts ) {
    $atts = shortcode_atts(
        array(
            'title' => 'Hello World',
        ),
        $atts,
        'test_plugin'
    );

    return '<div class="test-plugin">' . esc_html( $atts['title'] ) . '</div>';
}

add_shortcode( 'test_plugin', 'test_plugin_shortcode' );

function test_plugin_enqueue_scripts() {
    wp_enqueue_style( 'test-plugin-style', plugins_url( 'style.css', __FILE__ ) );
    wp_enqueue_script( 'test-plugin-script', plugins_url( 'script.js', __FILE__ ), array( 'jquery' ), '1.0.0', true );
}

add_action( 'wp_enqueue_scripts', 'test_plugin_enqueue_scripts' );

register_activation_hook( __FILE__, 'test_plugin_activate' );

function test_plugin_activate() {
    add_option( 'test_plugin_activated', true );
}
