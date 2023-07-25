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

    use Laminas\Authentication\Result as AuthenticationResult;
    use Laminas\Db\Adapter\Adapter as DbAdapter;
    use Laminas\Db\Sql;
    use Laminas\Db\Sql\Expression as SqlExpr;
    use Laminas\Db\Sql\Predicate\Operator as SqlOp;

    use function strpos;


    /**
     *
     */
    class CredentialTreatmentAdapter extends AbstractAdapter
    {
        /**
         * Tratamento aplicado à credencial, como MD5() ou PASSWORD().
         *
         * @var string.
         */
        protected $credentialTreatment;

        /**
         * __construct() - Sets configuration options
         *
         * @param string $tableName Opcional.
         * @param string $identityColumn Opcional.
         * @param string $credentialColumn Opcional.
         * @param string $credentialTreatment Opcional.
         */
        public function __construct(DbAdapter $laminasDb, $tableName = null, $identityColumn = null, $credentialColumn = null, $credentialTreatment = null)
        {
            parent::__construct($laminasDb, $tableName, $identityColumn, $credentialColumn);

            if (null !== $credentialTreatment)
            {
                $this->setCredentialTreatment($credentialTreatment);
            }
        }

        /**
         * Permite que o desenvolvedor passe uma string parametrizada
         * que é usada para transformar ou tratar os dados da
         * credencial de entrada.
         *
         * Em muitos casos, senhas e outros dados confidenciais são
         * criptografados, hash, codificados, obscurecidos ou tratados
         * de outra forma por meio de alguma função ou algoritmo. Ao
         * especificar uma sequência de tratamento parametrizada com
         * esse método, um desenvolvedor pode aplicar SQL arbitrário
         * aos dados de credencial de entrada.
         *
         * Exemplos:
         *     "PASSWORD(?)".
         *     "MD5(?)".
         *
         * @param string $treatment.
         * @return self Fornece uma interface fluente.
         */
        public function setCredentialTreatment($treatment)
        {
            $this->credentialTreatment = $treatment;

            return $this;
        }

        /**
         * Este método cria um objeto Laminas\Db\Sql\Select que está
         * completamente configurado para ser consultado no cubo de
         * dados.
         *
         * @return Sql\Select.
         */
        protected function authenticateCreateSelect()
        {
            /**
             * Criar expressão de credencial.
             */
            if (empty($this->credentialTreatment) || (strpos($this->credentialTreatment, "?") === false))
            {
                $this->credentialTreatment = "?";
            }

            $credentialExpression = new SqlExpr(
                "(CASE WHEN ? = " . $this->credentialTreatment . " THEN 1 ELSE 0 END) AS ?",
                [
                    $this->credentialColumn,
                    $this->credential,
                    "laminas_auth_credential_match"
                ],
                [
                    SqlExpr::TYPE_IDENTIFIER,
                    SqlExpr::TYPE_VALUE,
                    SqlExpr::TYPE_IDENTIFIER
                ]
            );

            /**
             * Obter ['select'].
             */
            $dbSelect = clone $this->getDbSelect();
            $dbSelect->from($this->tableName)
                ->columns(['*', $credentialExpression])
                ->where(new SqlOp($this->identityColumn, "=", $this->identity));

            return $dbSelect;
        }

        /**
         * Esse método tenta validar se o registro no conjunto de
         * resultados é realmente um registro que corresponde à
         * identificação fornecida a esse adaptador.
         *
         * @param  array $resultIdentity.
         * @return AuthenticationResult.
         */
        protected function authenticateValidateResult($resultIdentity)
        {
            /**
             * A partir do PHP 8.1.0 inteiros e flutuantes em conjuntos
             * de resultados serão retornados usando tipos PHP nativos
             * em vez de strings ao usar instruções preparadas emuladas.
             * Para manter o comportamento consistente com as versões
             * mais antigas do PHP, é usada uma comparação estrita de
             * ambos os tipos.
             *
             * @link https://www.php.com.br/manual/migration81.incompatible.php#migration81.incompatible.pdo.mysql
             */
            if ($resultIdentity["laminas_auth_credential_match"] !== "1" && $resultIdentity["laminas_auth_credential_match"] !== 1)
            {
                $this->authenticateResultInfo["code"] = AuthenticationResult::FAILURE_CREDENTIAL_INVALID;
                $this->authenticateResultInfo["messages"][] = "A credencial fornecida não é muito válida.";

                return $this->authenticateCreateAuthResult();
            }

            unset($resultIdentity["laminas_auth_credential_match"]);
            $this->resultRow = $resultIdentity;

            $this->authenticateResultInfo["code"] = AuthenticationResult::SUCCESS;
            $this->authenticateResultInfo["messages"][] = "Autenticação bem-sucedida.";

            return $this->authenticateCreateAuthResult();
        }
    }
