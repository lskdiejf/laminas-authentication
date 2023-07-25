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

    namespace Laminas\Authentication\Validator;

    use Laminas\Authentication\Adapter\ValidatableAdapterInterface;
    use Laminas\Authentication\AuthenticationService;
    use Laminas\Authentication\Exception;
    use Laminas\Authentication\Result;
    use Laminas\Stdlib\ArrayUtils;
    use Laminas\Validator\AbstractValidator;
    use Traversable;

    use function array_key_exists;
    use function gettype;
    use function is_array;
    use function is_object;
    use function is_string;
    use function sprintf;


    /**
     * Validador de autenticação.
     */
    class Authentication extends AbstractValidator
    {
        /**
         * Códigos de falha.
         *
         * @const string.
         */

        /**
         *
         */
        public const IDENTITY_NOT_FOUND = "identityNotFound";

        /**
         *
         */
        public const IDENTITY_AMBIGUOUS = "identityAmbiguous";

        /**
         *
         */
        public const CREDENTIAL_INVALID = "credentialInvalid";

        /**
         *
         */
        public const UNCATEGORIZED = "uncategorized";

        /**
         *
         */
        public const GENERAL = "general";

        /**
         * Mapeamento de códigos Authentication\Result.
         *
         * @const array.
         */
        public const CODE_MAP = [
            Result::FAILURE_IDENTITY_NOT_FOUND => self::IDENTITY_NOT_FOUND,
            Result::FAILURE_CREDENTIAL_INVALID => self::CREDENTIAL_INVALID,
            Result::FAILURE_IDENTITY_AMBIGUOUS => self::IDENTITY_AMBIGUOUS,
            Result::FAILURE_UNCATEGORIZED => self::UNCATEGORIZED,
        ];

        /**
         * códigos Authentication\Result mapeando substituições configuráveis.
         *
         * @var string[].
         */
        protected $codeMap = [];

        /**
         * Mensagens de falha.
         *
         * @var array.
         */
        protected $messageTemplates = [
            self::IDENTITY_NOT_FOUND => "Identificação não muito válida",
            self::IDENTITY_AMBIGUOUS => "A identificação é ambígua",
            self::CREDENTIAL_INVALID => "Senha inválida",
            self::UNCATEGORIZED => "Falha na autenticação",
            self::GENERAL => "Falha na autenticação"
        ];

        /**
         * Adaptador de autenticação.
         *
         * @var null|ValidatableAdapterInterface.
         */
        protected $adapter;

        /**
         * Identificação (ou campo).
         *
         * @var string.
         */
        protected $identity;

        /**
         * Credencial (ou campo).
         *
         * @var string.
         */
        protected $credential;

        /**
         * Serviço de autenticação.
         *
         * @var null|AuthenticationService.
         */
        protected $service;

        /**
         * Define as opções do validador.
         *
         * @param array<string, mixed>|Traversable<string, mixed> $options.
         */
        public function __construct($options = null)
        {
            if ($options instanceof Traversable)
            {
                $options = ArrayUtils::iteratorToArray($options);
            }

            if (is_array($options))
            {
                if (isset($options["adapter"]))
                {
                    $this->setAdapter($options["adapter"]);
                }

                if (isset($options["identity"]))
                {
                    $this->setIdentity($options["identity"]);
                }

                if (isset($options["credential"]))
                {
                    $this->setCredential($options["credential"]);
                }

                if (isset($options["service"]))
                {
                    $this->setService($options["service"]);
                }

                if (isset($options["code_map"]))
                {
                    foreach ($options["code_map"] as $code => $template)
                    {
                        if (empty($template) || ! is_string($template))
                        {
                            throw new Exception\InvalidArgumentException(
                                "A chave de mensagem na opção code_map deve ser " .
                                "uma string não vazia"
                            );
                        }

                        if (!isset($this->messageTemplates[$template]))
                        {
                            $this->messageTemplates[$template] = $this->messageTemplates[static::GENERAL];
                        }

                        $this->codeMap[(int) $code] = $template;
                    }
                }
            }

            parent::__construct($options);
        }

        /**
         * Obter Adaptador.
         *
         * @return null|ValidatableAdapterInterface.
         */
        public function getAdapter()
        {
            return $this->adapter;
        }

        /**
         * Definir Adaptador.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setAdapter(ValidatableAdapterInterface $adapter)
        {
            $this->adapter = $adapter;

            return $this;
        }

        /**
         * Obter identificação.
         *
         * @return mixed.
         */
        public function getIdentity()
        {
            return $this->identity;
        }

        /**
         * Definir identificação.
         *
         * @param mixed $identity.
         * @return self Fornece uma interface fluente.
         */
        public function setIdentity($identity)
        {
            $this->identity = $identity;

            return $this;
        }

        /**
         * Obter credencial.
         *
         * @return mixed.
         */
        public function getCredential()
        {
            return $this->credential;
        }

        /**
         * Definir credencial.
         *
         * @param mixed $credential.
         * @return self Fornece uma interface fluente.
         */
        public function setCredential($credential)
        {
            $this->credential = $credential;

            return $this;
        }

        /**
         * Obter serviço.
         *
         * @return null|AuthenticationService.
         */
        public function getService()
        {
            return $this->service;
        }

        /**
         * Definir serviço.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setService(AuthenticationService $service)
        {
            $this->service = $service;

            return $this;
        }

        /**
         * Retorna true se e somente se o resultado da autenticação for válido.
         *
         * Se o resultado da autenticação falhar na validação, esse método
         * retornará false e getMessages() retornará um vetor de mensagens
         * que explicam por que a validação falhou.
         *
         * @param null|mixed $value OPTIONAL Credencial (ou campo).
         * @param null|array $context OPTIONAL Dados de autenticação (identificação e/ou credencial).
         * @return bool.
         * @throws Exception\RuntimeException.
         */
        public function isValid($value = null, $context = null)
        {
            if ($value !== null)
            {
                $this->setCredential($value);
            }

            if ($this->identity === null)
            {
                throw new Exception\RuntimeException(
                    "A identificação deve ser definida antes da validação"
                );
            }

            $identity = ($context !== null) && array_key_exists($this->identity, $context)
                ? $context[$this->identity]
                : $this->identity;

            if ($this->credential === null)
            {
                throw new Exception\RuntimeException(
                    "A credencial deve ser definida antes da validação"
                );
            }

            $credential = ($context !== null) && array_key_exists($this->credential, $context)
                ? $context[$this->credential]
                : $this->credential;

            if (! $this->service)
            {
                throw new Exception\RuntimeException(
                    "AuthenticationService deve ser definido antes da validação"
                );
            }

            $adapter = $this->adapter ?: $this->getAdapterFromAuthenticationService();
            $adapter->setIdentity($identity);
            $adapter->setCredential($credential);
            $result = $this->service->authenticate($adapter);

            if ($result->isValid())
            {
                return true;
            }

            $messageKey = $this->mapResultCodeToMessageKey($result->getCode());
            $this->error($messageKey);

            return false;
        }

        /**
         * @param int $code Código do resultado da autenticação.
         * @return string Message chave que deve ser usada para o código.
         */
        protected function mapResultCodeToMessageKey($code)
        {
            if (isset($this->codeMap[$code]))
            {
                return $this->codeMap[$code];
            }

            if (array_key_exists($code, static::CODE_MAP))
            {
                return static::CODE_MAP[$code];
            }

            return self::GENERAL;
        }

        /**
         * @return ValidatableAdapterInterface.
         * @throws Exception\RuntimeException Se nenhum adaptador estiver presente no serviço de autenticação.
         * @throws Exception\RuntimeException Se o adaptador presente no serviço de autenticação não for uma instância ValidatableAdapterInterface.
         */
        private function getAdapterFromAuthenticationService()
        {
            if (!$this->service)
            {
                throw new Exception\RuntimeException(
                    "O adaptador deve ser definido antes da validação"
                );
            }

            $adapter = $this->service->getAdapter();

            if (!$adapter)
            {
                throw new Exception\RuntimeException(
                    "O adaptador deve ser definido antes da validação"
                );
            }

            if (!$adapter instanceof ValidatableAdapterInterface)
            {
                throw new Exception\RuntimeException(
                    sprintf(
                        "O adaptador deve ser uma instância de %s; %s informado",
                        ValidatableAdapterInterface::class,
                        is_object($adapter) ? $adapter::class : gettype($adapter)
                    )
                );
            }

            return $adapter;
        }
    }
