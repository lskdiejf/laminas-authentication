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

    use Exception;
    use Laminas\Authentication\Exception\InvalidArgumentException;
    use Laminas\Authentication\Exception\RuntimeException;
    use Laminas\Authentication\Result;

    use function call_user_func;
    use function is_callable;

    /**
     * Autenticação O adaptador autentica usando a função
     * de retorno de chamada.
     *
     * A função Callback deve retornar uma identificação em caso
     * de sucesso na autenticação e false em caso de falha na
     * autenticação.
     */
    class Callback extends AbstractAdapter
    {
        /**
         * @var callable.
         */
        protected $callback;

        /**
         * @param callable $callback O retorno de chamada de autenticação.
         */
        public function __construct($callback = null)
        {
            if (null !== $callback)
            {
                $this->setCallback($callback);
            }
        }

        /**
         * Autentique usando o retorno de chamada fornecido.
         *
         * @return Resultado O resultado da autenticação.
         * @throws RuntimeException.
         */
        public function authenticate()
        {
            $callback = $this->getCallback();

            if (!$callback)
            {
                throw new RuntimeException("Nenhum retorno de chamada fornecido");
            }

            try
            {
                $identity = call_user_func($callback, $this->getIdentity(), $this->getCredential());
            } catch (Exception $e)
            {
                return new Result(Result::FAILURE_UNCATEGORIZED, null, [$e->getMessage()]);
            }

            if (!$identity)
            {
                return new Result(Result::FAILURE, null, ["Falha de autenticação"]);
            }

            return new Result(Result::SUCCESS, $identity, ["Sucesso na autenticação"]);
        }

        /**
         * Obtém o valor do retorno de chamada.
         *
         * @return null|callable.
         */
        public function getCallback()
        {
            return $this->callback;
        }

        /**
         * Define o valor do retorno de chamada.
         *
         * @param callable $callback o retorno de chamada.
         * @throws InvalidArgumentException.
         * @return void.
         */
        public function setCallback($callback)
        {
            if (!is_callable($callback))
            {
                throw new InvalidArgumentException("Retorno de chamada não muito válido fornecido");
            }

            $this->callback = $callback;
        }
    }
