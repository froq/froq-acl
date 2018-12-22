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

use Froq\Service\Service;

/**
 * @package    Froq
 * @subpackage Froq\Acl
 * @object     Froq\Acl\Acl
 * @author     Kerem Güneş <k-gun@mail.com>
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
     * Service.
     * @var Froq\Service\Service
     */
    private $service;

    /**
     * User.
     * @var Froq\Acl\User
     */
    private $user;

    /**
     * Rules (comes from <FooService>/config['acl.config'] if provided).
     * @var array
     */
    private $rules = [];

    /**
     * Constructor.
     * @param Froq\Service\Service $service
     */
    public function __construct(Service $service)
    {
        $this->service = $service;
    }

    /**
     * Get service.
     * @return Froq\Service\Service
     */
    public function getService(): Service
    {
        return $this->service;
    }

    /**
     * Set user.
     * @param  Froq\Acl\User $user
     * @return void
     */
    public function setUser(User $user): void
    {
        $this->user = $user;
        $this->user->setAcl($this);

        $userRole = $this->user->getRole();
        if ($userRole != null && !empty($this->rules)) {
            foreach ($this->rules as $role => $rules) {
                if ($userRole == $role) {
                    foreach ($rules as $uri => $rules) {
                        $this->user->setPermissionsOf($uri, (array) explode(',', $rules) /* 'read,write' etc. */);
                    }
                    break;
                }
            }
        }
    }

    /**
     * Get user.
     * @return ?Froq\Acl\User
     */
    public function getUser(): ?User
    {
        return $this->user;
    }

    /**
     * Set rules.
     * @param  array $rules
     * @return void
     */
    public function setRules(array $rules): void
    {
        $this->rules = $rules;
    }

    /**
     * Get rules.
     * @return array
     */
    public function getRules(): array
    {
        return $this->rules;
    }
}
