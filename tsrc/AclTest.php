<?php
/**
 * Acl / Test.
 * @command ~/.composer/vendor/bin/phpunit --verbose --colors=auto --bootstrap=./_boot.php ./
 */
use froq\acl\Acl;

class AclTest extends PHPUnit\Framework\TestCase
{
    function test_nullUser() {
        $this->assertNull((new Acl)->getUser());
    }

    function test_nullRules() {
        $this->assertNull((new Acl)->getRules());
    }
}
