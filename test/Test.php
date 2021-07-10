<?php
/**
 * Acl / Test.
 * @command ~/.composer/vendor/bin/phpunit --colors=auto Test.php
 */
namespace froq\acl\test;

require __dir__ . '/../../../../vendor/autoload.php';

use froq\acl\{Acl, User};
use PHPUnit\Framework\TestCase;

class Test extends TestCase
{
    function test_nullUser() {
        $this->assertNull((new Acl)->getUser());
        $this->assertNotNull((new Acl(new User))->getUser());
    }

    function test_userId() {
        $this->assertEquals(1, (new User(1))->getId());
        $this->assertEquals(null, (new User(null))->getId());
    }

    function test_userIsLoggedIn() {
        $this->assertTrue((new User(1, 'Doe John'))->isLoggedIn());
        $this->assertFalse((new User(null, 'Foe John'))->isLoggedIn());
    }

    function test_userHasAccessTo() {
        $user1 = new User(1, 'Doe');
        $user2 = new User(2, 'Foe');

        $user1->setPermissionsOf('/posts', ['read', 'write']);
        $user2->setPermissionsOf('/posts', []);

        $this->assertTrue($user1->hasAccessTo('/posts'));
        $this->assertFalse($user2->hasAccessTo('/posts'));
    }

    function test_userCanRead() {
        $user1 = new User(1, 'Doe');
        $user2 = new User(2, 'Foe');

        $user1->setPermissionsOf('/posts', ['read']);
        $user2->setPermissionsOf('/posts', []);

        $this->assertTrue($user1->canRead('/posts'));
        $this->assertFalse($user2->canRead('/posts'));
    }

    function test_userCanWrite() {
        $user1 = new User(1, 'Doe');
        $user2 = new User(2, 'Foe');

        $user1->setPermissionsOf('/posts', ['write']);
        $user2->setPermissionsOf('/posts', []);

        $this->assertTrue($user1->canWrite('/posts'));
        $this->assertFalse($user2->canWrite('/posts'));
    }

    function test_userCanReadAndWrite() {
        $user1 = new User(1, 'Doe');
        $user2 = new User(2, 'Foe');

        // $user1->setPermissionsOf('/posts', ['all']); // Or.
        $user1->setPermissionsOf('/posts', ['read', 'write']);
        $user2->setPermissionsOf('/posts', []);

        $this->assertTrue($user1->canRead('/posts') or $user1->canWrite('/posts'));
        $this->assertFalse($user2->canRead('/posts') or $user2->canWrite('/posts'));
    }
}
