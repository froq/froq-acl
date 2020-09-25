<?php
/**
 * MIT License <https://opensource.org/licenses/mit>
 *
 * Copyright (c) 2015 Kerem Güneş
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
declare(strict_types=1);

namespace froq\acl;

use froq\acl\{Acl, AclException};

/**
 * User.
 * @package froq\acl
 * @object  froq\acl\User
 * @author  Kerem Güneş <k-gun@mail.com>
 * @since   1.0
 */
final class User
{
    /**
     * Acl.
     * @var froq\acl\Acl.
     */
    private Acl $acl;

    /**
     * Id.
     * @var int|string
     */
    private $id;

    /**
     * Name.
     * @var string
     */
    private string $name;

    /**
     * Role.
     * @var string
     */
    private string $role;

    /**
     * Permissions.
     * @var array
     */
    private array $permissions;

    /**
     * Constructor.
     * @param int|string|null $id
     * @param string|null     $name
     * @param string|null     $role
     */
    public function __construct($id = null, string $name = null, string $role = null)
    {
        $id   && $this->setId($id);
        $name && $this->setName($name);
        $role && $this->setRole($role);
    }

    /**
     * Set acl.
     * @param  froq\acl\Acl $acl
     * @return void
     */
    public function setAcl(Acl $acl): void
    {
        $this->acl = $acl;
    }

    /**
     * Get Acl.
     * @return ?froq\acl\Acl
     */
    public function getAcl(): ?Acl
    {
        return ($this->acl ?? null);
    }

    /**
     * Set id.
     * @param  int|string $id
     * @return void
     * @throws froq\acl\AclException
     */
    public function setId($id): void
    {
        if (!is_int($id) && !is_string($id)) {
            throw new AclException(sprintf('Only int and string IDs are accepted, %s given',
                gettype($id)));
        }

        $this->id = $id;
    }

    /**
     * Get id.
     * @return ?int|?string
     */
    public function getId()
    {
        return ($this->id ?? null);
    }

    /**
     * Set name.
     * @param  string $name
     * @return void
     */
    public function setName(string $name): void
    {
        $this->name = $name;
    }

    /**
     * Get name.
     * @return ?string
     */
    public function getName(): ?string
    {
        return ($this->name ?? null);
    }


    /**
     * Set role.
     * @param  string $role
     * @return void
     */
    public function setRole(string $role): void
    {
        $this->role = $role;
    }

    /**
     * Get role.
     * @return ?string
     */
    public function getRole(): ?string
    {
        return ($this->role ?? null);
    }

    /**
     * Set permissions.
     * @param  array $permissions
     * @return void
     */
    public function setPermissions(array $permissions): void
    {
        $this->permissions = $permissions;
    }

    /**
     * Get permissions.
     * @return ?array
     */
    public function getPermissions(): ?array
    {
        return ($this->permissions ?? null);
    }

    /**
     * Set permission of.
     * @param  string $uri
     * @param  array  $permission
     * @return void
     */
    public function setPermissionsOf(string $uri, array $permission): void
    {
        $this->permissions[$uri] = $permission;
    }

    /**
     * Get permission of.
     * @param  string $uri
     * @return ?array
     */
    public function getPermissionsOf(string $uri): ?array
    {
        return ($this->getPermissions()[$uri] ?? null);
    }

    /**
     * Is logged in.
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return ($this->getId() != null);
    }

    /**
     * Has access to.
     * @param  string $uri
     * @return bool
     */
    public function hasAccessTo(string $uri): bool
    {
        return ($this->getPermissionsOf($uri) != null);
    }

    /**
     * Can read.
     * @param  string $uri
     * @return bool
     */
    public function canRead(string $uri): bool
    {
        // /book => all
        $uriRoot = $this->getUriRoot($uri);
        if (in_array(Acl::RULE_ALL, (array) $this->getPermissionsOf($uriRoot))) {
            return true;
        }

        // /book/detail => all or read
        $permission = array_filter((array) $this->getPermissionsOf($uri), function ($rule) {
            return ($rule == Acl::RULE_ALL || $rule == Acl::RULE_READ);
        });

        return ($permission != null);
    }

    /**
     * Can write.
     * @param  string $uri
     * @return bool
     */
    public function canWrite(string $uri): bool
    {
        // /book => all
        $uriRoot = $this->getUriRoot($uri);
        if (in_array(Acl::RULE_ALL, (array) $this->getPermissionsOf($uriRoot))) {
            return true;
        }

        // /book/detail => all or write
        $permission = array_filter((array) $this->getPermissionsOf($uri), function ($rule) {
            return ($rule == Acl::RULE_ALL || $rule == Acl::RULE_WRITE);
        });

        return ($permission != null);
    }

    /**
     * Info.
     * @param  bool $full
     * @return string
     */
    public function info(bool $full = false): string
    {
        $ret = sprintf('%s: id=%s(%s)', $this->getRole(), $this->getId(), $this->getName());

        if ($full) {
            foreach ((array) $this->getPermissions() as $uri => $rules) {
                $ret .= sprintf("\n uri(%s %s)", $uri, implode(',', $rules));
            }
        }

        return $ret;
    }

    /**
     * Get uri root.
     * @param  string $uri
     * @return string
     */
    private function getUriRoot(string $uri): string
    {
        $uri .= '/'; // ensure slash

        return substr($uri, 0, strpos($uri, '/', 1));
    }
}
