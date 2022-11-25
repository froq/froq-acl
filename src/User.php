<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-acl
 */
declare(strict_types=1);

namespace froq\acl;

use froq\common\trait\DataTrait;

/**
 * A class, defines its ACL with rules and provides an ability to run ACL related routines.
 *
 * @package froq\acl
 * @object  froq\acl\User
 * @author  Kerem Güneş
 * @since   1.0
 */
class User
{
    use DataTrait;

    /** @var froq\acl\Acl */
    protected Acl $acl;

    /** @var int|string */
    private int|string $id;

    /** @var string */
    private string $name;

    /** @var string */
    private string $role;

    /** @var array */
    private array $permissions;

    /** @var array */
    private array $data = [];

    /**
     * Constructor.
     *
     * @param int|string|null $id
     * @param string|null     $name
     * @param string|null     $role
     * @param array|null      $permissions
     * @param array|null      $data
     */
    public function __construct(int|string $id = null, string $name = null, string $role = null,
        array $permissions = null, array $data = null)
    {
        $id          && $this->setId($id);
        $name        && $this->setName($name);
        $role        && $this->setRole($role);
        $permissions && $this->setPermissions($permissions);

        if ($data) {
            $this->setData($data);

            // Add spesific fields.
            isset($data['id'])   && $this->setId($data['id']);
            isset($data['name']) && $this->setName($data['name']);
        }
    }

    /**
     * Set ACL property.
     *
     * @param  froq\acl\Acl $acl
     * @return self
     */
    public function setAcl(Acl $acl): self
    {
        $this->acl = $acl;

        return $this;
    }

    /**
     * Get ACL property.
     *
     * @return froq\acl\Acl|null
     */
    public function getAcl(): Acl|null
    {
        return $this->acl ?? null;
    }

    /**
     * Set id.
     *
     * @param  int|string $id
     * @return self
     */
    public function setId(int|string $id): self
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Get id.
     *
     * @return int|string|null
     */
    public function getId(): int|string|null
    {
        return $this->id ?? null;
    }

    /**
     * Set name.
     *
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
     *
     * @return string|null
     */
    public function getName(): string|null
    {
        return $this->name ?? null;
    }


    /**
     * Set role.
     *
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
     * @return string|null
     */
    public function getRole(): string|null
    {
        return $this->role ?? null;
    }

    /**
     * Set permissions.
     *
     * @param  array $permissions
     * @return self
     */
    public function setPermissions(array $permissions): self
    {
        foreach ($permissions as $uri => $rules) {
            $this->setPermissionsOf($uri, $rules);
        }

        return $this;
    }

    /**
     * Get permissions.
     *
     * @return array|null
     */
    public function getPermissions(): array|null
    {
        return $this->permissions ?? null;
    }

    /**
     * Set permissions of.
     *
     * @param  string       $uri
     * @param  string|array $rules
     * @return self
     */
    public function setPermissionsOf(string $uri, string|array $rules): self
    {
        // Eg: "read" or "read,write".
        is_string($rules) && $rules = explode(',', $rules);

        $this->permissions[$uri] = $rules;

        return $this;
    }

    /**
     * Get permissions of.
     *
     * @param  string $uri
     * @return array|null
     */
    public function getPermissionsOf(string $uri): array|null
    {
        return $this->permissions[$uri] ?? null;
    }

    /**
     * Check logged-in state by id existence.
     *
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return $this->getId() != null;
    }

    /**
     * Check has-access-to state for an URI path.
     *
     * @param  string $uri
     * @return bool
     */
    public function hasAccessTo(string $uri): bool
    {
        return $this->getPermissionsOf($uri) != null;
    }

    /**
     * Check can-read state by given URI path.
     *
     * @param  string $uri
     * @return bool
     */
    public function canRead(string $uri): bool
    {
        // Eg: /book => all.
        $uriRoot = $this->extractUriRoot($uri);
        if (in_array(Rule::ALL, (array) $this->getPermissionsOf($uriRoot), true)) {
            return true;
        }

        // Eg: /book/detail => all or read.
        return !!array_filter((array) $this->getPermissionsOf($uri),
            fn($rule): bool => $rule === Rule::ALL || $rule === Rule::READ);
    }

    /**
     * Check can-write state by given URI path.
     *
     * @param  string $uri
     * @return bool
     */
    public function canWrite(string $uri): bool
    {
        // Eg: /book => all.
        $uriRoot = $this->extractUriRoot($uri);
        if (in_array(Rule::ALL, (array) $this->getPermissionsOf($uriRoot), true)) {
            return true;
        }

        // Eg: /book/detail => all or write.
        return !!array_filter((array) $this->getPermissionsOf($uri),
            fn($rule): bool => $rule === Rule::ALL || $rule === Rule::WRITE);
    }

    /**
     * Get user info.
     *
     * @param  bool $full
     * @return string
     */
    public function info(bool $full = false): string
    {
        $ret = sprintf(
            '%s: id=%s(%s)',
            $this->getRole() ?? '?',
            $this->getId()   ?? '?',
            $this->getName() ?? '?'
        );

        if ($full) {
            foreach ((array) $this->getPermissions() as $uri => $rules) {
                $ret .= sprintf("\n uri(%s %s)", $uri, join(',', $rules));
            }
        }

        return $ret;
    }

    /**
     * Extract root of given URI.
     *
     * @param  string $uri
     * @return string
     */
    private function extractUriRoot(string $uri): string
    {
        $uri .= '/'; // Ensure slash.

        return substr($uri, 0, strpos($uri, '/', 1));
    }
}
