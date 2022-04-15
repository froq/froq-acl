<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-acl
 */
declare(strict_types=1);

namespace froq\acl;

/**
 * A class, defines its user and provides an ability to run ACL related routines.
 *
 * @package froq\acl
 * @object  froq\acl\Acl
 * @author  Kerem Güneş
 * @since   1.0
 */
class Acl
{
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
        $userRole = $user->getRole();
        if ($userRole) {
            foreach ((array) $this->getRules() as $role => $rules) {
                // Eg: "user" or "admin".
                if ($userRole == $role) {
                    // Eg: ["/book" => "read"].
                    foreach ($rules as $uri => $permission) {
                        // Eg: "read" or "read,write".
                        $permission = explode(',', $permission);
                        $user->setPermissionsOf($uri, $permission);
                    }
                    break;
                }
            }
        }

        $this->user = $user;
        $this->user->setAcl($this);

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
