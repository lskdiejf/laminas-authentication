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

    use Laminas\Authentication\Exception\ExceptionInterface;


    /**
     *
     */
    interface StorageInterface
    {
        /**
         * Retorna verdadeiro se e somente se o armazenamento estiver vazio.
         *
         * @throws ExceptionInterface Se for impossível determinar se o armazenamento está vazio.
         * @return bool.
         */
        public function isEmpty();

        /**
         * Retorna o conteúdo do armazenamento.
         * O comportamento é indefinido quando o armazenamento está vazio.
         *
         * @throws ExceptionInterface Se a leitura do conteúdo do armazenamento for impossível.
         * @return mixed.
         */
        public function read();

        /**
         * Grava $contents no armazenamento.
         *
         * @param  mixed $contents.
         * @throws ExceptionInterface Se gravar $contents no armazenamento for impossível.
         * @return void.
         */
        public function write($contents);

        /**
         * Limpa o conteúdo do armazenamento.
         *
         * @throws ExceptionInterface Se limpar o conteúdo do armazenamento for impossível.
         * @return void.
         */
        public function clear();
    }
