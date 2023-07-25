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

    namespace Laminas\Authentication\Storage;

    use Laminas\Session\Container as SessionContainer;
    use Laminas\Session\ManagerInterface as SessionManager;


    /**
     *
     */
    class Session implements StorageInterface
    {
        /**
         * Namespace de sessão normal.
         */
        public const NAMESPACE_DEFAULT = "Laminas_Auth";

        /**
         * Nome do membro do objeto de sessão normal.
         */
        public const MEMBER_DEFAULT = "storage";

        /**
         * Objeto para proxy de armazenamento $_SESSION.
         *
         * @var SessionContainer.
         */
        protected $session;

        /**
         * Espaço de nomes de sessão.
         *
         * @var mixed.
         */
        protected $namespace = self::NAMESPACE_DEFAULT;

        /**
         * Membro do objeto de sessão.
         *
         * @var mixed.
         */
        protected $member = self::MEMBER_DEFAULT;

        /**
         * Define opções de armazenamento de sessão e inicializa
         * o objeto de namespace de sessão.
         *
         * @param  mixed $namespace.
         * @param  mixed $member.
         */
        public function __construct($namespace = null, $member = null, ?SessionManager $manager = null)
        {
            if ($namespace !== null)
            {
                $this->namespace = $namespace;
            }

            if ($member !== null)
            {
                $this->member = $member;
            }

            $this->session = new SessionContainer($this->namespace, $manager);
        }

        /**
         * Retorna o namespace da sessão.
         *
         * @return string.
         */
        public function getNamespace()
        {
            return $this->namespace;
        }

        /**
         * Retorna o nome do membro do objeto da sessão.
         *
         * @return string.
         */
        public function getMember()
        {
            return $this->member;
        }

        /**
         * Definido por Laminas\Authentication\Storage\StorageInterface.
         *
         * @return bool.
         */
        public function isEmpty()
        {
            return !isset($this->session->{$this->member});
        }

        /**
         * Definido por Laminas\Authentication\Storage\StorageInterface.
         *
         * @return mixed.
         */
        public function read()
        {
            return $this->session->{$this->member};
        }

        /**
         * Definido por Laminas\Authentication\Storage\StorageInterface.
         *
         * @param  mixed $contents.
         * @return void.
         */
        public function write($contents)
        {
            $this->session->{$this->member} = $contents;
        }

        /**
         * Definido por Laminas\Authentication\Storage\StorageInterface.
         *
         * @return void.
         */
        public function clear()
        {
            unset($this->session->{$this->member});
        }
    }
