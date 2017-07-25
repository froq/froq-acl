<?php
/**
 * Copyright (c) 2016 Kerem Güneş
 *     <k-gun@mail.com>
 *
 * GNU General Public License v3.0
 *     <http://www.gnu.org/licenses/gpl-3.0.txt>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
    final public function __construct(array $info = null)
    {
        if ($info) {
            isset($info['id'])   && $this->setId($info['id']);
            isset($info['name']) && $this->setName($info['name']);
            isset($info['role']) && $this->setRole($info['role']);
        }
    }

    /**
     * Set acl.
     * @param  Froq\Acl\Acl $acl
     * @return self
     */
    final public function setAcl(Acl $acl): self
    {
        $this->acl = $acl;

        return $this;
    }

    /**
     * Get Acl.
     * @return Froq\Acl\Acl|null
     */
    final public function getAcl()
    {
        return $this->acl;
    }

    /**
     * Set id.
     * @param  int|string $id
     * @return self
     */
    final public function setId($id): self
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Get id.
     * @return int|string
     */
    final public function getId()
    {
        return $this->id;
    }

    /**
     * Set name.
     * @param  string $name
     * @return self
     */
    final public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get name.
     * @return string
     */
    final public function getName()
    {
        return $this->name;
    }


    /**
     * Set role.
     * @param  string $role
     * @return self
     */
    final public function setRole(string $role): self
    {
        $this->role = $role;

        return $this;
    }

    /**
     * Get role.
     * @return string|null
     */
    final public function getRole()
    {
        return $this->role;
    }

    /**
     * Set permissions.
     * @param  array $permissions
     * @return self
     */
    final public function setPermissions(array $permissions): self
    {
        $this->permissions = $permissions;

        return $this;
    }

    /**
     * Get permissions.
     * @return array
     */
    final public function getPermissions(): array
    {
        return $this->permissions;
    }

    /**
     * Set permission of.
     * @param  string $uri
     * @param  array  $permission
     * @return self
     */
    final public function setPermissionsOf($uri, array $permission): self
    {
        $this->permissions[$uri] = $permission;

        return $this;
    }

    /**
     * Get permission of.
     * @param  string $uri
     * @return array|null
     */
    final public function getPermissionsOf($uri)
    {
        return $this->permissions[$uri] ?? null;
    }

    /**
     * Is logged in.
     * @return bool
     */
    final public function isLoggedIn(): bool
    {
        return $this->id !== null;
    }

    /**
     * Has access to.
     * @param  string $uri
     * @return bool
     */
    final public function hasAccessTo(string $uri): bool
    {
        return !!$this->getPermissionsOf($uri);
    }

    /**
     * Can read.
     * @param  string $uri
     * @return bool
     */
    final public function canRead(string $uri): bool
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
    final public function canWrite(string $uri): bool
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
     * @param  string $inOut
     * @param  string $to
     * @param  bool   $exit
     * @return void
     */
    final public function redirectIf(string $inOut, string $to = '/', bool $exit = true)
    {
        if ($this->acl) {
            $app = $this->acl->getService()->getApp();
            if ($inOut == 'in' && $this->isLoggedIn()) {
                return $app->response()->redirect($to);
            } elseif ($inOut == 'out' && !$this->isLoggedIn()) {
                return $app->response()->redirect($to);
            }
        } elseif (headers_sent($file, $line)) {
            throw new AclException(sprintf('Cannot use %s, headers was already sent in %s:%s', __method__, $file, $line));
        }

        header('Location: '. trim($to));
        if ($exit) {
            exit;
        }
    }

    /**
     * Info.
     * @param  bool $full
     * @return string
     */
    final public function info(bool $full = false): string
    {
        $return = sprintf('%s: id=%s(%s)', $this->role, $this->id, $this->name);
        if ($full) {
            foreach ($this->permissions as $uri => $rules) {
                $return .= sprintf("\n uri(%s %s)", $uri, join(',', $rules));
            }
        }

        return $return;
    }

    /**
     * Get root uri.
     * @param  string $uri
     * @return string
     */
    final private function getUriRoot(string $uri): string
    {
        $uri .= '/'; // ensure slash

        return substr($uri, 0, strpos($uri, '/', 1));
    }
}
