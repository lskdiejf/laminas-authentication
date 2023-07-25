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
     * Fornece uma API para autenticação e gerenciamento
     * de identificação.
     */
    interface AuthenticationServiceInterface
    {
        /**
         * Autentica e fornece um resultado de autenticação.
         *
         * @return Result.
         */
        public function authenticate();

        /**
         * Retorna true se e somente se uma identificação
         * estiver disponível.
         *
         * @return bool.
         */
        public function hasIdentity();

        /**
         * Retorna a identificação autenticada ou null se nenhuma
         * identificação estiver disponível.
         *
         * @return mixed|null.
         */
        public function getIdentity();

        /**
         * Limpa a identificação.
         *
         * @return void.
         */
        public function clearIdentity();
    }
