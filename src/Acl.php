<?php declare(strict_types=1);
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 · http://github.com/froq/froq-acl
 */
namespace froq\acl;

/**
 * A class, defines its user and provides an ability to run ACL related routines.
 *
 * @package froq\acl
 * @class   froq\acl\Acl
 * @author  Kerem Güneş
 * @since   1.0
 */
class Acl
{
    /** User instance. */
    private User $user;

    /** Rules. */
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
     * Set user.
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
                if ($userRole === $role) {
                    // Eg: ["/book" => "read"].
                    foreach ($rules as $uri => $rule) {
                        // Eg: "read" or "read,write".
                        $user->setPermissionsTo($uri, $rule);
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
     * Get user.
     *
     * @return froq\acl\User|null
     */
    public function getUser(): User|null
    {
        return $this->user ?? null;
    }

    /**
     * Set rules.
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
     * Get rules.
     *
     * @return array|null
     */
    public function getRules(): array|null
    {
        return $this->rules ?? null;
    }
}
