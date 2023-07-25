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

    namespace Laminas\Authentication\Adapter\Http;

    /**
     * Interface do resolvedor HTTP de autenticação.
     *
     * Define uma interface para resolver uma combinação
     * de nome da pessoa/domínio em um segredo compartilhado
     * utilizável pela autenticação HTTP.
     */
    interface ResolverInterface
    {
        /**
         * Resolva nome de pessoa/domínio para senha/hash/etc.
         *
         * @param  string $username Nome da pessoa.
         * @param  string $realm Domínio de Autenticação
         * @param  string $password Senha (opcional).
         * @return string|array|false Segredo compartilhado da pessoa
         *                            como string, se encontrado no Domínio,
         *                            ou identificador da pessoa como vetor,
         *                            se resolvido; caso contrário, falso.
         */
        public function resolve($username, $realm, $password = null);
    }
