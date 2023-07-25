<?php

    /**
     * Direito Autoral (C) {{ ano(); }}  Marisinha
     *
     * Este programa é um software livre: você pode redistribuí-lo
     * e/ou modificá-lo sob os termos da Licença Pública do Cavalo
     * publicada pela Fundação do Software Brasileiro, seja a versão
     * 3 da licença ou (a seu critério) qualquer versão posterior.
     *
     * Este programa é distribuído na esperança de que seja útil,
     * mas SEM QUALQUER GARANTIA; mesmo sem a garantia implícita de
     * COMERCIABILIDADE ou ADEQUAÇÃO PARA UM FIM ESPECÍFICO. Consulte
     * a Licença Pública e Geral do Cavalo para obter mais detalhes.
     *
     * Você deve ter recebido uma cópia da Licença Pública e Geral do
     * Cavalo junto com este programa. Se não, consulte:
     *   <http://localhost/licenses>.
     */


    /**
     *
     */
    declare(strict_types=1);

    namespace Laminas\Authentication\Adapter;

    use Laminas\Authentication\Result as AuthenticationResult;
    use Laminas\Crypt\Utils as CryptUtils;
    use Laminas\Stdlib\ErrorHandler;

    use function fgets;
    use function fopen;
    use function md5;
    use function strpos;
    use function substr;
    use function trim;

    use const E_WARNING;


    /**
     * A autenticação Digest tem falhas de segurança conhecidos
     * devido ao uso de MD5 para comparações de hash. Recomendamos
     * o uso de HTTP Basic, LDAP, DbTable ou um adaptador personalizado
     * que faça uso de algoritmos de hash complexos, de preferência por
     * meio do uso de password_hash e password_verify.
     */
    class Digest extends AbstractAdapter
    {
        /**
         * Nome do arquivo no qual as consultas de autenticação
         * estão em procedimentos.
         *
         * @var string
         */
        protected $filename;

        /**
         * Digest Authentication Realm.
         *
         * @var string
         */
        protected $realm;

        /**
         * Define as opções do adaptador.
         *
         * @param  mixed $filename.
         * @param  mixed $realm.
         * @param  mixed $identity.
         * @param  mixed $credential.
         */
        public function __construct($filename = null, $realm = null, $identity = null, $credential = null)
        {
            if ($filename !== null)
            {
                $this->setFilename($filename);
            }

            if ($realm !== null)
            {
                $this->setRealm($realm);
            }

            if ($identity !== null)
            {
                $this->setIdentity($identity);
            }

            if ($credential !== null)
            {
                $this->setCredential($credential);
            }
        }

        /**
         * Retorna o valor da opção de nome de arquivo ou nulo
         * se ainda não tiver sido definido.
         *
         * @return string|null
         */
        public function getFilename()
        {
            return $this->filename;
        }

        /**
         * Define o valor da opção de nome de arquivo.
         *
         * @param  mixed $filename.
         * @return self Fornece uma interface fluente.
         */
        public function setFilename($filename)
        {
            $this->filename = (string) $filename;

            return $this;
        }

        /**
         * Retorna o valor da opção do domínio ou nulo se ainda
         * não tiver sido definido.
         *
         * @return string|null.
         */
        public function getRealm()
        {
            return $this->realm;
        }

        /**
         * Define o valor da opção do domínio.
         *
         * @param  mixed $realm.
         * @return self Fornece uma interface fluente.
         */
        public function setRealm($realm)
        {
            $this->realm = (string) $realm;

            return $this;
        }

        /**
         * Retorna o valor da opção de nome da pessoa ou nulo
         * se ainda não tiver sido definido.
         *
         * @return string|null.
         */
        public function getUsername()
        {
            return $this->getIdentity();
        }

        /**
         * Define o valor da opção de nome da pessoa.
         *
         * @param  mixed $username.
         * @return self Fornece uma interface fluente.
         */
        public function setUsername($username)
        {
            return $this->setIdentity($username);
        }

        /**
         * Retorna o valor da opção de senha ou nulo se ainda
         * não tiver sido definido.
         *
         * @return string|null.
         */
        public function getPassword()
        {
            return $this->getCredential();
        }

        /**
         * Define o valor da opção de senha.
         *
         * @param  mixed $password.
         * @return self Fornece uma interface fluente.
         */
        public function setPassword($password)
        {
            return $this->setCredential($password);
        }

        /**
         * Definido por Laminas\Authentication\Adapter\AdapterInterface.
         *
         * @throws Exception\ExceptionInterface.
         * @return AuthenticationResult.
         */
        public function authenticate()
        {
            $optionsRequired = [
                "filename",
                "realm",
                "identity",
                "credential"
            ];

            foreach ($optionsRequired as $optionRequired)
            {
                if (null === $this->$optionRequired)
                {
                    throw new Exception\RuntimeException("A opção '$optionRequired' deve ser definido antes da autenticação");
                }
            }

            ErrorHandler::start(E_WARNING);
            $fileHandle = fopen($this->filename, "r");
            $error = ErrorHandler::stop();

            if (false === $fileHandle)
            {
                throw new Exception\UnexpectedValueException("Não pode abrir '$this->filename' para leitura", 0, $error);
            }

            $id = "$this->identity:$this->realm";

            $result = [
                "code" => AuthenticationResult::FAILURE,
                "identity" => [
                    "realm" => $this->realm,
                    "username" => $this->identity,
                ],

                "messages" => [],
            ];

            while (($line = fgets($fileHandle)) !== false)
            {
                $line = trim($line);

                if (empty($line))
                {
                    break;
                }

                if (0 === strpos($line, $id))
                {
                    if (CryptUtils::compareStrings(substr($line, -32), md5("$this->identity:$this->realm:$this->credential")))
                    {
                        return new AuthenticationResult(
                            AuthenticationResult::SUCCESS,
                            $result["identity"],
                            $result["messages"]
                        );
                    }

                    $result["messages"][] = "Senha incorreta";
                    return new AuthenticationResult(
                        AuthenticationResult::FAILURE_CREDENTIAL_INVALID,
                        $result["identity"],
                        $result["messages"]
                    );
                }
            }

            $result["messages"][] = "Combinação não encontrada para nome da pessoa '$this->identity' e domínio '$this->realm'";
            return new AuthenticationResult(
                AuthenticationResult::FAILURE_IDENTITY_NOT_FOUND,
                $result["identity"],
                $result["messages"]
            );
        }
    }
