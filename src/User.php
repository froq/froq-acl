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

namespace Froq\Acl;

/**
 * @package    Froq
 * @subpackage Froq\Acl
 * @object     Froq\Acl\User
 * @author     Kerem Güneş <k-gun@mail.com>
 */
final class User
{
    /**
     * Acl.
     * @var Froq\Acl\Acl.
     */
    private $acl;

    /**
     * Id.
     * @var int|string
     */
    private $id;

    /**
     * Name.
     * @var string
     */
    private $name;

    /**
     * Role.
     * @var string
     */
    private $role;

    /**
     * Permissions.
     * @var array
     */
    private $permissions = [];

    /**
     * Constructor.
     * @param array|null $info
     */
    public function __construct(array $info = null)
    {
        if ($info != null) {
            isset($info['id'])   && $this->setId($info['id']);
            isset($info['name']) && $this->setName($info['name']);
            isset($info['role']) && $this->setRole($info['role']);
        }
    }

    /**
     * Set acl.
     * @param  Froq\Acl\Acl $acl
     * @return void
     */
    public function setAcl(Acl $acl): void
    {
        $this->acl = $acl;
    }

    /**
     * Get Acl.
     * @return ?Froq\Acl\Acl
     */
    public function getAcl(): ?Acl
    {
        return $this->acl;
    }

    /**
     * Set id.
     * @param  int|string $id
     * @return void
     */
    public function setId($id): void
    {
        $this->id = $id;
    }

    /**
     * Get id.
     * @return ?int|?string
     */
    public function getId()
    {
        return $this->id;
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
        return $this->name;
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
        return $this->role;
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
     * @return array
     */
    public function getPermissions(): array
    {
        return $this->permissions;
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
        return $this->permissions[$uri] ?? null;
    }

    /**
     * Is logged in.
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return null !== $this->id;
    }

    /**
     * Has access to.
     * @param  string $uri
     * @return bool
     */
    public function hasAccessTo(string $uri): bool
    {
        return null !== $this->getPermissionsOf($uri);
    }

    /**
     * Can read.
     * @param  string $uri
     * @return bool
     */
    public function canRead(string $uri): bool
    {
        // /book => all
        if (in_array(Acl::RULE_ALL, (array) $this->getPermissionsOf($this->getUriRoot($uri)))) {
            return true;
        }

        // /book/detail => all or read
        $permission = array_filter((array) $this->getPermissionsOf($uri), function($rule) {
            return ($rule == Acl::RULE_ALL || $rule == Acl::RULE_READ);
        });

        return !empty($permission);
    }

    /**
     * Can write.
     * @param  string $uri
     * @return bool
     */
    public function canWrite(string $uri): bool
    {
        // /book => all
        if (in_array(Acl::RULE_ALL, (array) $this->getPermissionsOf($this->getUriRoot($uri)))) {
            return true;
        }

        // /book/detail => all or write
        $permission = array_filter((array) $this->getPermissionsOf($uri), function($rule) {
            return ($rule == Acl::RULE_ALL || $rule == Acl::RULE_WRITE);
        });

        return !empty($permission);
    }

    /**
     * Redirect if.
     * @param  string $dir In/out direction.
     * @param  string $to
     * @param  bool   $exit
     * @return void
     */
    public function redirectIf(string $dir, string $to = '/', bool $exit = true): void
    {
        if ($this->acl != null) {
            $app = $this->acl->getService()->getApp();
            if ($dir == 'in' && $this->isLoggedIn()) {
                $app->response()->redirect($to);
            } elseif ($dir == 'out' && !$this->isLoggedIn()) {
                $app->response()->redirect($to);
            }
        } else {
            if (headers_sent($file, $line)) {
                throw new AclException(sprintf("Cannot use '%s()', headers already sent in %s:%s",
                    __method__, $file, $line));
            }

            header('Location: '. trim($to));
            if ($exit) {
                exit(0);
            }
        }
    }

    /**
     * Info.
     * @param  bool $full
     * @return string
     */
    public function info(bool $full = false): string
    {
        $return = sprintf('%s: id=%s(%s)', $this->role, $this->id, $this->name);
        if ($full) {
            foreach ($this->permissions as $uri => $rules) {
                $return .= sprintf("\n uri(%s %s)", $uri, implode(',', $rules));
            }
        }

        return $return;
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
