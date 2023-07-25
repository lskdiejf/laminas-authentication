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
    class Result
    {
        /**
         * Falha comum.
         */
        public const FAILURE = 0;

        /**
         * Falha devido à identificação não encontrada.
         */
        public const FAILURE_IDENTITY_NOT_FOUND = -1;

        /**
         * Falha devido à identificação ser ambígua.
         */
        public const FAILURE_IDENTITY_AMBIGUOUS = -2;

        /**
         * Falha devido ao fornecimento de credencial não muito válida.
         */
        public const FAILURE_CREDENTIAL_INVALID = -3;

        /**
         * Falha devido a razões não categorizadas.
         */
        public const FAILURE_UNCATEGORIZED = -4;

        /**
         * Sucesso na autenticação.
         */
        public const SUCCESS = 1;

        /**
         * Código do resultado da autenticação.
         *
         * @var int.
         */
        protected $code;

        /**
         * A identificação usada na tentativa de autenticação.
         *
         * @var mixed.
         */
        protected $identity;

        /**
         * Um vetor de strings com os motivos pelos quais a tentativa
         * de autenticação não foi bem-sucedida. Se a autenticação
         * for bem-sucedida, deve ser um vetor vazio.
         *
         * @var array.
         */
        protected $messages;

        /**
         * Define o código de resultado, a identificação e as
         * mensagens de falha.
         *
         * @param int $code.
         * @param mixed $identity.
         * @param array $messages.
         */
        public function __construct($code, $identity, array $messages = [])
        {
            $this->code = (int) $code;
            $this->identity = $identity;
            $this->messages = $messages;
        }

        /**
         * Retorna se o resultado representa uma tentativa de
         * autenticação bem-sucedida.
         *
         * @return bool.
         */
        public function isValid()
        {
            return $this->code > 0;
        }

        /**
         * Obtenha o código de resultado para esta tentativa
         * de autenticação.
         *
         * @return int.
         */
        public function getCode()
        {
            return $this->code;
        }

        /**
         * Retorna a identificação utilizada na tentativa de autenticação.
         *
         * @return mixed.
         */
        public function getIdentity()
        {
            return $this->identity;
        }

        /**
         * Retorna um vetor de strings com os motivos pelos quais
         * a tentativa de autenticação não foi bem-sucedida. Se
         * a autenticação for bem-sucedida, esse método retornará
         * um vetor vazio.
         *
         * @return array
         */
        public function getMessages()
        {
            return $this->messages;
        }
    }
