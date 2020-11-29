<?php
/**
 * Copyright (c) 2015 · Kerem Güneş
 * Apache License 2.0 <https://opensource.org/licenses/apache-2.0>
 */
declare(strict_types=1);

namespace froq\acl;

use froq\acl\User;

/**
 * Acl.
 *
 * @package froq\acl
 * @object  froq\acl\Acl
 * @author  Kerem Güneş <k-gun@mail.com>
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

    /**
     * User.
     * @var froq\acl\User
     */
    private User $user;

    /**
     * Rules.
     * @var array<string, array<string>>
     */
    private array $rules;

    /**
     * Constructor.
     * @param froq\acl\User|null                $user
     * @param array<string, array<string>>|null $rules
     */
    public function __construct(User $user = null, array $rules = null)
    {
        $user && $this->setUser($user);
        $rules && $this->setRules($rules);
    }

    /**
     * Set user.
     * @param  froq\acl\User $user
     * @return void
     */
    public function setUser(User $user): void
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
    }

    /**
     * Get user.
     * @return ?froq\acl\User
     */
    public function getUser(): ?User
    {
        return $this->user ?? null;
    }

    /**
     * Set rules.
     * @param  array<string, array<string>> $rules
     * @return void
     */
    public function setRules(array $rules): void
    {
        $this->rules = $rules;
    }

    /**
     * Get rules.
     * @return ?array<string, array<string>>
     */
    public function getRules(): ?array
    {
        return $this->rules ?? null;
    }
}
