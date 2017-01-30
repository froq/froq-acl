<?php
declare(strict_types=1);

namespace Froq\Acl;

use Froq\Util\Traits\GetterTrait;
use Froq\Service\Service;

final class Acl
{
    use GetterTrait;

    const RULE_ALL   = 'all',
          RULE_READ  = 'read',
          RULE_WRITE = 'write';

    private $service;
    private $user;
    private $rules = []; // extract from service.config["acl.config"]

    final public function __construct(Service $service)
    {
        $this->service = $service;
    }

    final public function setUser(User $user)
    {
        $userRole = $user->getRole();
        if ($userRole && !empty($this->rules)) {
            foreach ($this->rules as $role => $rules) {
                if ($role == $userRole) {
                    foreach ($rules as $uri => $rule) {
                                                   // 'read,write' etc.
                        $user->setPermission($uri, explode(',', $rule));
                    }
                    break;
                }
            }
        }

        $this->user = $user;
    }
    final public function getUser()
    {
        return $this->user;
    }

    final public function setRules(array $rules)
    {
        $this->rules = $rules;
    }
    final public function getRules(): array
    {
        return $this->rules;
    }
}
