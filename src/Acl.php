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

use froq\acl\User;

/**
 * Acl.
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
     * Rules.
     * @var array<string, array<string, string>>
     */
    private array $rules;

    /**
     * User.
     * @var froq\acl\User
     */
    private User $user;

    /**
     * Constructor.
     * @param array<string, array<string, string>>|null $rules
     * @param froq\acl\User|null                        $user
     */
    public function __construct(array $rules = null, User $user = null)
    {
        $rules && $this->setRules($rules);
        $user  && $this->setUser($user);
    }

    /**
     * Set rules.
     * @param  array<string, array<string, string>> $rules
     * @return void
     */
    public function setRules(array $rules): void
    {
        $this->rules = $rules;
    }

    /**
     * Get rules.
     * @return ?array<string, array<string, string>>
     */
    public function getRules(): ?array
    {
        return $this->rules ?? null;
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
}
