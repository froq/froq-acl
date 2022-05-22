<?php
/**
 * Acl / Test.
 * @command ~/.composer/vendor/bin/phpunit --verbose --colors --bootstrap=./_boot.php ./
 */

$froqFolder = __dir__ . '/../../';
$froqLoader = __dir__ . '/../../froq/src/Autoloader.php';
if (is_file($froqLoader)) {
    include $froqLoader;
    $loader = froq\Autoloader::init($froqFolder);
    $loader->register();
    // return;
}

$composerLoader = $froqFolder . '/vendor/autoload.php';
if (is_file($composerLoader)) {
    $loader = include $composerLoader;
    $loader->addPsr4('froq\\acl\\', __dir__ . '/../src/');

    $composerJson = file_get_contents(__dir__ . '/../composer.json');
    $composerData = json_decode($composerJson, true);

    // Load deps.
    foreach ($composerData['require'] as $package => $_) {
        if (substr($package, 0, 5) == 'froq/') {
            $package = substr($package, 5);
            $packagePrefix = strtr($package, '-', '\\') . '\\';
            $packageSource = $froqFolder . $package . '/src/';
            $loader->addPsr4($packagePrefix, $packageSource);
        }
    }
    // Load files.
    if (isset($composerData['autoload']['files'])) {
        foreach ($composerData['autoload']['files'] as $file) {
            include $file;
        }
    }
}
