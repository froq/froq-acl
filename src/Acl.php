<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq
 */
declare(strict_types=1);

namespace froq\acl;

use froq\acl\User;

/**
 * Acl.
 *
 * Represents an ACL entity which holds its user and provides an ability to run ACL related routines with that
 * user interface.
 *
 * @package froq\acl
 * @object  froq\acl\Acl
 * @author  Kerem Güneş
 * @since   1.0
 */
final class Acl
{
    /**
     * Rules.
     * @const string
     */
    public const RULE_ALL   = 'all',
                 RULE_READ  = 'read',
                 RULE_WRITE = 'write';

    /** @var froq\acl\User */
    private User $user;

    /** @var array */
    private array $rules;

    /**
     * Constructor.
     *
     * @param froq\acl\User|null $user
     * @param array|null         $rules
     */
    public function __construct(User $user = null, array $rules = null)
    {
        $user  && $this->setUser($user);
        $rules && $this->setRules($rules);
    }

    /**
     * Set ACL user.
     *
     * @param  froq\acl\User $user
     * @return self
     */
    public function setUser(User $user): self
    {
        $this->user = $user;
        $this->user->setAcl($this);

        $userRole = $this->user->getRole();
        if ($userRole != null) {
            foreach ((array) $this->getRules() as $role => $rules) {
                if ($userRole == $role) { // Eg: "user" or "admin".
                    foreach ($rules as $uri => $permission) { // Eg: ["/book" => "read"].
                        $permission = (array) explode(',', $permission); // Eg: "read" or "read,write".
                        $this->user->setPermissionsOf($uri, $permission);
                    }
                    break;
                }
            }
        }

        return $this;
    }

    /**
     * Get ACL user.
     *
     * @return froq\acl\User|null
     */
    public function getUser(): User|null
    {
        return $this->user ?? null;
    }

    /**
     * Set ACL user rules.
     *
     * @param  array $rules
     * @return self
     */
    public function setRules(array $rules): self
    {
        $this->rules = $rules;

        return $this;
    }

    /**
     * Get ACL user rules.
     *
     * @return array|null
     */
    public function getRules(): array|null
    {
        return $this->rules ?? null;
    }
}
