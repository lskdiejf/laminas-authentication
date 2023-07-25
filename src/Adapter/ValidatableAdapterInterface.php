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


    /**
     *
     */
    interface ValidatableAdapterInterface extends AdapterInterface
    {
        /**
         * Retorna a identificação da conta que está sendo autenticada
         * ou NULL se nenhuma for definida.
         *
         * @return mixed.
         */
        public function getIdentity();

        /**
         * Define a identificação para ligação.
         *
         * @param  mixed $identity.
         * @return ValidatableAdapterInterface.
         */
        public function setIdentity($identity);

        /**
         * Retorna a credencial da conta que está sendo autenticada
         * ou NULL se nenhuma estiver definida.
         *
         * @return mixed.
         */
        public function getCredential();

        /**
         * Define a credencial para vinculação.
         *
         * @param  mixed $credential.
         * @return ValidatableAdapterInterface.
         */
        public function setCredential($credential);
    }
