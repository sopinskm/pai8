<?php

namespace Admin\Service;


use Laminas\Authentication\Adapter\DbTable\CallbackCheckAdapter as AuthAdapter;
use Laminas\Authentication\AuthenticationService;
use Laminas\Crypt\Password\Bcrypt;
use Laminas\Db\Adapter\AdapterInterface;
use Admin\Service\Logi;

class AuthService
{
    /**
     * AuthService constructor.
     *
     * @param AdapterInterface      $adapter
     * @param AuthenticationService $authenticationService
     */
    public function __construct(private AdapterInterface $adapter, private AuthenticationService $authenticationService)
    {
    }

    /**
     * Przeprowadza autentykację użytkownika
     *
     * @param string $login
     * @param string $haslo
     * @return boolean
     */
    public function auth(string $login, string $haslo): bool
    {

        $logger = new Logi($this->adapter);

        if (empty($login)) {
            return false;
        }

        $adapter = new AuthAdapter(
            $this->adapter,
            'uzytkownicy',
            'login',
            'haslo',
            fn(string $hash, string $haslo) => (new Bcrypt())->verify($haslo, $hash)
        );
        $adapter->setIdentity($login)->setCredential($haslo);

        $wynik = $adapter->authenticate();
        if ($wynik->isValid()) {
            $dane = $adapter->getResultRowObject(null, ['haslo']);
            $this->authenticationService->getStorage()->write($dane);
            $logger->sendInfoLog($login .  " prawidłowe logowanie");
            return true;
        }
        $logger->sendInfoLog("Błąd autoryzacji");
        return false;
    }

    public function clear()
    {
        $logger = new Logi($this->adapter);
        $this->authenticationService->clearIdentity();
        $logger->sendInfoLog("Wylogowanie");
    }

    public function loggedIn(): bool
    {
        return $this->authenticationService->hasIdentity();
    }

    public function getIdentity()
    {
        return $this->authenticationService->getIdentity();
    }
}
