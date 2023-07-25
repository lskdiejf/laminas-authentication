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

    namespace Laminas\Authentication;


    /**
     *
     */
    class AuthenticationService implements AuthenticationServiceInterface
    {
        /**
         * Modificador de armazenamento persistente.
         *
         * @var Storage\StorageInterface.
         */
        protected $storage;

        /**
         * Adaptador de autenticação.
         *
         * @var Adapter\AdapterInterface.
         */
        protected $adapter;

        /**
         * Inicializador.
         */
        public function __construct(?Storage\StorageInterface $storage = null, ?Adapter\AdapterInterface $adapter = null)
        {
            if (null !== $storage)
            {
                $this->setStorage($storage);
            }

            if (null !== $adapter)
            {
                $this->setAdapter($adapter);
            }
        }

        /**
         * Retorna o adaptador de autenticação. O adaptador não tem
         * uma especificação caso o adaptador de armazenamento não
         * tenha sido configurado.
         *
         * @return Adapter\AdapterInterface|null.
         */
        public function getAdapter()
        {
            return $this->adapter;
        }

        /**
         * Define o adaptador de autenticação.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setAdapter(Adapter\AdapterInterface $adapter)
        {
            $this->adapter = $adapter;

            return $this;
        }

        /**
         * Returns the persistent storage handler. O armazenamento
         * de sessão é usado normalmente, a menos que um adaptador
         * de armazenamento diferente tenha sido definido.
         *
         * @return Storage\StorageInterface.
         */
        public function getStorage()
        {
            if (null === $this->storage)
            {
                $this->setStorage(new Storage\Session());
            }

            return $this->storage;
        }

        /**
         * Define o modificador de armazenamento persistente.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setStorage(Storage\StorageInterface $storage)
        {
            $this->storage = $storage;

            return $this;
        }

        /**
         * Autentica no adaptador fornecido.
         *
         * @return Result.
         * @throws Exception\RuntimeException.
         */
        public function authenticate(?Adapter\AdapterInterface $adapter = null)
        {
            if (!$adapter)
            {
                if (!$adapter = $this->getAdapter())
                {
                    throw new Exception\RuntimeException(
                        "Um adaptador deve ser definido ou passado antes da " .
                        "chamada authenticate()"
                    );
                }
            }

            $result = $adapter->authenticate();

            /**
             * Laminas-7546 - evitar que várias chamadas sucessivas
             * armazenem resultados inconsistentes. Certifique-se
             * de que o armazenamento esteja limpo.
             */
            if ($this->hasIdentity())
            {
                $this->clearIdentity();
            }

            if ($result->isValid())
            {
                $this->getStorage()->write($result->getIdentity());
            }

            return $result;
        }

        /**
         * Retorna verdadeiro se e somente se uma identificação
         * estiver disponível no armazenamento.
         *
         * @return bool.
         */
        public function hasIdentity()
        {
            return !$this->getStorage()->isEmpty();
        }

        /**
         * Retorna a identificação do armazenamento ou null se
         * nenhuma identificação estiver disponível.
         *
         * @return mixed|null.
         */
        public function getIdentity()
        {
            $storage = $this->getStorage();

            if ($storage->isEmpty())
            {
                return;
            }

            return $storage->read();
        }

        /**
         * Limpa a identificação do armazenamento persistente.
         *
         * @return void.
         */
        public function clearIdentity()
        {
            $this->getStorage()->clear();
        }
    }
