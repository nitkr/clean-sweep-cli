<?php
define('WP_USE_THEMES', true);
require './wp-load.php';
wp();
ob_start();
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <title><?php bloginfo( 'name' ); ?></title>
</head>
<body>
    <?php if ( have_posts() ) : while ( have_posts() ) : the_post(); ?>
        <h1><?php the_title(); ?></h1>
        <div><?php the_content(); ?></div>
    <?php endwhile; endif; ?>
</body>
</html>