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

    /**
     * Armazenamento de autenticação não persistente.
     *
     * Como a autenticação HTTP ocorre novamente a cada solicitação,
     * ela sempre será preenchida novamente. Portanto, não há necessidade
     * de usar sessões, essa classe de valor simples manterá os dados
     * para o restante da solicitação atual.
     */
    class NonPersistent implements StorageInterface
    {
        /**
         * Mantém os dados de autenticação reais.
         *
         * @var mixed.
         */
        protected $data;

        /**
         * Retorna verdadeiro se e somente se o armazenamento
         * estiver vazio.
         *
         * @return bool.
         */
        public function isEmpty()
        {
            return empty($this->data);
        }

        /**
         * Retorna o conteúdo do armazenamento. O comportamento
         * é indefinido quando o armazenamento está vazio.
         *
         * @return mixed.
         */
        public function read()
        {
            return $this->data;
        }

        /**
         * Grava $contents no armazenamento.
         *
         * @param  mixed $contents.
         * @return void.
         */
        public function write($contents)
        {
            $this->data = $contents;
        }

        /**
         * Limpa o conteúdo do armazenamento.
         *
         * @return void.
         */
        public function clear()
        {
            $this->data = null;
        }
    }
