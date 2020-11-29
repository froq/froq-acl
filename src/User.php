<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\acl;

use froq\acl\{Acl, AclException};

/**
 * User.
 *
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
     * @param array|null      $permissions
     */
    public function __construct($id = null, string $name = null, string $role = null,
        array $permissions = null)
    {
        $id  && $this->setId($id);
        $name && $this->setName($name);
        $role && $this->setRole($role);
        $permissions && $this->setPermissions($permissions);
    }

    /**
     * Set acl.
     * @param  froq\acl\Acl $acl
     * @return self
     */
    public function setAcl(Acl $acl): self
    {
        $this->acl = $acl;

        return $this;
    }

    /**
     * Get Acl.
     * @return ?froq\acl\Acl
     */
    public function getAcl(): ?Acl
    {
        return $this->acl ?? null;
    }

    /**
     * Set id.
     * @param  int|string $id
     * @return self
     * @throws froq\acl\AclException
     */
    public function setId($id): self
    {
        if (!is_int($id) && !is_string($id)) {
            throw new AclException(sprintf('Only int and string IDs are accepted, %s given',
                gettype($id)));
        }

        $this->id = $id;

        return $this;
    }

    /**
     * Get id.
     * @return ?int|?string
     */
    public function getId()
    {
        return $this->id ?? null;
    }

    /**
     * Set name.
     * @param  string $name
     * @return self
     */
    public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get name.
     * @return ?string
     */
    public function getName(): ?string
    {
        return $this->name ?? null;
    }


    /**
     * Set role.
     * @param  string $role
     * @return self
     */
    public function setRole(string $role): self
    {
        $this->role = $role;

        return $this;
    }

    /**
     * Get role.
     * @return ?string
     */
    public function getRole(): ?string
    {
        return $this->role ?? null;
    }

    /**
     * Set permissions.
     * @param  array $permissions
     * @return self
     */
    public function setPermissions(array $permissions): self
    {
        $this->permissions = $permissions;

        return $this;
    }

    /**
     * Get permissions.
     * @return ?array
     */
    public function getPermissions(): ?array
    {
        return $this->permissions ?? null;
    }

    /**
     * Set permissions of.
     * @param  string $uri
     * @param  array  $rules
     * @return self
     */
    public function setPermissionsOf(string $uri, array $rules): self
    {
        $this->permissions[$uri] = $rules;

        return $this;
    }

    /**
     * Get permissions of.
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
        return $this->getId() != null;
    }

    /**
     * Has access to.
     * @param  string $uri
     * @return bool
     */
    public function hasAccessTo(string $uri): bool
    {
        return $this->getPermissionsOf($uri) != null;
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
        return !!array_filter((array) $this->getPermissionsOf($uri), function ($rule) {
            return ($rule == Acl::RULE_ALL || $rule == Acl::RULE_READ);
        });
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
        return !!array_filter((array) $this->getPermissionsOf($uri), function ($rule) {
            return ($rule == Acl::RULE_ALL || $rule == Acl::RULE_WRITE);
        });
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
