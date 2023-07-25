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

    namespace Laminas\Authentication\Adapter\DbTable;

    use Exception;
    use Laminas\Authentication\Adapter\DbTable\Exception\InvalidArgumentException;
    use Laminas\Authentication\Result as AuthenticationResult;
    use Laminas\Db\Adapter\Adapter as DbAdapter;
    use Laminas\Db\Sql;
    use Laminas\Db\Sql\Predicate\Operator as SqlOp;

    use function call_user_func;
    use function is_callable;


    /**
     *
     */
    class CallbackCheckAdapter extends AbstractAdapter
    {
        /**
         * Isso substitui o uso de tratamento para fornecer um
         * retorno de chamada que permite que a validação
         * ocorra no código.
         *
         * @var callable.
         */
        protected $credentialValidationCallback;

        /**
         * Define as opções de configuração.
         *
         * @param string $tableName Opcional.
         * @param string $identityColumn Opcional.
         * @param string $credentialColumn Opcional.
         * @param callable $credentialValidationCallback Opcional.
         */
        public function __construct(DbAdapter $laminasDb, $tableName = null, $identityColumn = null, $credentialColumn = null, $credentialValidationCallback = null)
        {
            parent::__construct($laminasDb, $tableName, $identityColumn, $credentialColumn);

            if (null !== $credentialValidationCallback)
            {
                $this->setCredentialValidationCallback($credentialValidationCallback);
            } else
            {
                $this->setCredentialValidationCallback(function ($a, $b)
                {
                    return $a === $b;
                });
            }
        }

        /**
         * Permite que o desenvolvedor use um retorno de chamada como
         * forma de verificar a credencial.
         *
         * @param callable $validationCallback.
         * @return self Provides a fluent interface.
         * @throws InvalidArgumentException.
         */
        public function setCredentialValidationCallback($validationCallback)
        {
            if (!is_callable($validationCallback))
            {
                throw new InvalidArgumentException("Retorno de chamada inválido fornecido");
            }

            $this->credentialValidationCallback = $validationCallback;

            return $this;
        }

        /**
         * Este método cria um objeto Laminas\Db\Sql\Select que
         * está completamente configurado para ser consultado
         * no cubo de dados.
         *
         * @return Sql\Select.
         */
        protected function authenticateCreateSelect()
        {
            /**
             * Obter ['select'].
             */
            $dbSelect = clone $this->getDbSelect();
            $dbSelect->from($this->tableName)
                ->columns([Sql\Select::SQL_STAR])
                ->where(new SqlOp($this->identityColumn, '=', $this->identity));

            return $dbSelect;
        }

        /**
         * Esse método tenta validar se o registro no conjunto
         * de resultados é realmente um registro que corresponde
         * à identidade fornecida a esse adaptador.
         *
         * @param array $resultIdentity.
         * @return AuthenticationResult.
         */
        protected function authenticateValidateResult($resultIdentity)
        {
            try
            {
                $callbackResult = call_user_func(
                    $this->credentialValidationCallback,
                    $resultIdentity[$this->credentialColumn],
                    $this->credential
                );
            } catch (Exception $e)
            {
                $this->authenticateResultInfo["code"] = AuthenticationResult::FAILURE_UNCATEGORIZED;
                $this->authenticateResultInfo["messages"][] = $e->getMessage();

                return $this->authenticateCreateAuthResult();
            }

            if ($callbackResult !== true)
            {
                $this->authenticateResultInfo["code"] = AuthenticationResult::FAILURE_CREDENTIAL_INVALID;
                $this->authenticateResultInfo["messages"][] = "A credencial fornecida não é muito válida.";

                return $this->authenticateCreateAuthResult();
            }

            $this->resultRow = $resultIdentity;
            $this->authenticateResultInfo["code"] = AuthenticationResult::SUCCESS;
            $this->authenticateResultInfo["messages"][] = "Autenticação bem-sucedida.";

            return $this->authenticateCreateAuthResult();
        }
    }
