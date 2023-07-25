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
    use Laminas\Authentication\Adapter\AbstractAdapter as BaseAdapter;
    use Laminas\Authentication\Adapter\DbTable\Exception\RuntimeException;
    use Laminas\Authentication\Result as AuthenticationResult;
    use Laminas\Db\Adapter\Adapter as DbAdapter;
    use Laminas\Db\Sql;
    use stdClass;

    use function array_keys;
    use function count;
    use function in_array;
    use function is_bool;
    use function is_int;


    /**
     *
     */
    abstract class AbstractAdapter extends BaseAdapter
    {
        /**
         * Conexão de banco de dados.
         *
         * @var DbAdapter.
         */
        protected $laminasDb;

        /**
         * @var Sql\Select.
         */
        protected $dbSelect;

        /**
         * O nome da tabela para verificar.
         *
         * @var string.
         */
        protected $tableName;

        /**
         * A pilastra a ser usada como a identificação.
         *
         * @var string
         */
        protected $identityColumn;

        /**
         * pilastras a serem usadas como credenciais.
         *
         * @var string.
         */
        protected $credentialColumn;

        /**
         * @var array.
         */
        protected $authenticateResultInfo;

        /**
         * Resultados da consulta de autenticação do cubo de dados.
         *
         * @var array.
         */
        protected $resultRow;

        /**
         * Sinalizador para indicar que a mesma identificação pode ser
         * usada com credenciais diferentes. A especificação é FALSE e
         * precisa ser definido como true para permitir o uso de
         * ambigüidade.
         *
         * @var bool.
         */
        protected $ambiguityIdentity = false;

        /**
         * Define as opções de configuração.
         *
         * @param string    $tableName           Optional
         * @param string    $identityColumn      Optional
         * @param string    $credentialColumn    Optional
         */
        public function __construct(DbAdapter $laminasDb, $tableName = null, $identityColumn = null, $credentialColumn = null)
        {
            $this->laminasDb = $laminasDb;

            if (null !== $tableName)
            {
                $this->setTableName($tableName);
            }

            if (null !== $identityColumn)
            {
                $this->setIdentityColumn($identityColumn);
            }

            if (null !== $credentialColumn)
            {
                $this->setCredentialColumn($credentialColumn);
            }
        }

        /**
         * Defina o nome da tabela a ser usado na consulta de seleção.
         *
         * @param string $tableName.
         * @return self Fornece uma interface fluente.
         */
        public function setTableName($tableName)
        {
            $this->tableName = $tableName;

            return $this;
        }

        /**
         * Defina o nome da pilastra a ser usado como a pilastra
         * de identificação.
         *
         * @param string $identityColumn.
         * @return self Fornece uma interface fluente.
         */
        public function setIdentityColumn($identityColumn)
        {
            $this->identityColumn = $identityColumn;

            return $this;
        }

        /**
         * Defina o nome da pilastra a ser usado como pilastra de credencial.
         *
         * @param  string $credentialColumn.
         * @return self Fornece uma interface fluente.
         */
        public function setCredentialColumn($credentialColumn)
        {
            $this->credentialColumn = $credentialColumn;

            return $this;
        }

        /**
         * Define um sinalizador para uso de identificações idênticas
         * com credenciais exclusivas. Aceita parâmetros inteiros (0, 1)
         * ou booleanos (true, false). Normalmente é false.
         *
         * @param  int|bool $flag.
         * @return self Provides uma interface fluente.
         */
        public function setAmbiguityIdentity($flag)
        {
            if (is_int($flag))
            {
                $this->ambiguityIdentity = 1 === $flag;
            } elseif (is_bool($flag))
            {
                $this->ambiguityIdentity = $flag;
            }

            return $this;
        }

        /**
         * Retorna TRUE para uso de várias identificações idênticas
         * com credenciais diferentes, FALSE se não for usado.
         *
         * @return bool
         */
        public function getAmbiguityIdentity()
        {
            return $this->ambiguityIdentity;
        }

        /**
         * Retorne o objeto Db Select de pré-autenticação para a
         * modificação da consulta de seleção da área da pessoa.
         *
         * @return Sql\Select.
         */
        public function getDbSelect()
        {
            if ($this->dbSelect === null)
            {
                $this->dbSelect = new Sql\Select();
            }

            return $this->dbSelect;
        }

        /**
         * Retorna a linha de resultado como um objeto stdClass.
         *
         * @param string|array $returnColumns.
         * @param string|array $omitColumns.
         * @return stdClass|bool.
         */
        public function getResultRowObject($returnColumns = null, $omitColumns = null)
        {
            if (!$this->resultRow)
            {
                return false;
            }

            $returnObject = new stdClass();

            if (null !== $returnColumns)
            {
                $availableColumns = array_keys($this->resultRow);
                foreach ((array) $returnColumns as $returnColumn)
                {
                    if (in_array($returnColumn, $availableColumns))
                    {
                        $returnObject->{$returnColumn} = $this->resultRow[$returnColumn];
                    }
                }

                return $returnObject;
            } elseif (null !== $omitColumns)
            {
                $omitColumns = (array) $omitColumns;
                foreach ($this->resultRow as $resultColumn => $resultValue)
                {
                    if (! in_array($resultColumn, $omitColumns))
                    {
                        $returnObject->{$resultColumn} = $resultValue;
                    }
                }

                return $returnObject;
            }

            foreach ($this->resultRow as $resultColumn => $resultValue)
            {
                $returnObject->{$resultColumn} = $resultValue;
            }

            return $returnObject;
        }

        /**
         * Este método é chamado para tentar uma autenticação. Antes dessa
         * chamada, esse adaptador já teria sido configurado com todas as
         * informações necessárias para se conectar com êxito a uma tabela
         * de banco de dados e tentar localizar um registro correspondente
         * à identificação fornecida.
         *
         * @throws RuntimeException Se responder à consulta de autenticação for impossível.
         * @return AuthenticationResult.
         */
        public function authenticate()
        {
            $this->authenticateSetup();
            $dbSelect = $this->authenticateCreateSelect();
            $resultIdentities = $this->authenticateQuerySelect($dbSelect);

            if (($authResult = $this->authenticateValidateResultSet($resultIdentities)) instanceof AuthenticationResult)
            {
                return $authResult;
            }

            /**
             * Neste ponto, a ambigüidade já está feita.
             * Ciclo, verifique e faça a concluão no sucesso.
             */
            foreach ($resultIdentities as $identity)
            {
                $authResult = $this->authenticateValidateResult($identity);

                if ($authResult->isValid())
                {
                    break;
                }
            }

            return $authResult;
        }

        /**
         * Esse método tenta validar se o registro no conjunto de
         * resultados é realmente um registro que corresponde à
         * identificação fornecida a esse adaptador.
         *
         * @param array $resultIdentity.
         * @return AuthenticationResult.
         */
        abstract protected function authenticateValidateResult($resultIdentity);

        /**
         * Este método cria um objeto Laminas\Db\Sql\Select que está
         * completamente configurado para ser consultado no cubo
         * de dados.
         *
         * @return Sql\Select.
         */
        abstract protected function authenticateCreateSelect();

        /**
         * Este método abstrai as etapas envolvidas para garantir
         * que este adaptador foi realmente configurado corretamente
         * com todas as informações necessárias.
         *
         * @throws RuntimeException Caso a configuração não tenha sido feita corretamente.
         * @return bool.
         */
        protected function authenticateSetup()
        {
            $exception = null;

            if ((string) $this->tableName === "")
            {
                $exception = "Uma tabela deve ser fornecida para o adaptador de autenticação DbTable.";
            } elseif ((string) $this->identityColumn === "")
            {
                $exception = "Uma pilastra de identificação deve ser fornecida para o adaptador de autenticação DbTable.";
            } elseif ((string) $this->credentialColumn === "")
            {
                $exception = "Uma pilastra de credencial deve ser fornecida para o adaptador de autenticação DbTable.";
            } elseif ((string) $this->identity === "")
            {
                $exception = "Um valor para a identificação não foi fornecido antes da autenticação com DbTable.";
            } elseif ($this->credential === null)
            {
                $exception = "Um valor de credencial não foi fornecido antes da autenticação com DbTable.";
            }

            if (null !== $exception)
            {
                throw new RuntimeException($exception);
            }

            $this->authenticateResultInfo = [
                "code" => AuthenticationResult::FAILURE,
                "identity" => $this->identity,
                "messages" => [],
            ];

            return true;
        }

        /**
         * Este método aceita um objeto Laminas\Db\Sql\Select e faz
         * o procedimento de uma consulta no cubo de dados com
         * esse objeto.
         *
         * @throws RuntimeException Quando um objeto de seleção não muito válido é encontrado.
         * @return array
         */
        protected function authenticateQuerySelect(Sql\Select $dbSelect)
        {
            $sql = new Sql\Sql($this->laminasDb);
            $statement = $sql->prepareStatementForSqlObject($dbSelect);

            try
            {
                $result = $statement->execute();
                $resultIdentities = [];

                /**
                 * Iterar o resultado, da maneira mais multiplataforma.
                 */
                foreach ($result as $row)
                {
                    /**
                     * Laminas-6428 - conta para mecanismos de cubo de dados
                     * que, normalmente, retornam nomes de pilastra em
                     * maiúsculas
                     */
                    if (isset($row["LAMINAS_AUTH_CREDENTIAL_MATCH"]))
                    {
                        $row["laminas_auth_credential_match"] = $row["LAMINAS_AUTH_CREDENTIAL_MATCH"];

                        unset($row["LAMINAS_AUTH_CREDENTIAL_MATCH"]);
                    }

                    $resultIdentities[] = $row;
                }
            } catch (Exception $e)
            {
                throw new RuntimeException(
                    "Os parâmetros fornecidos para DbTable falharam em " .
                    "produzir uma instrução sql válida, verifique a validade " .
                    "dos nomes das tabelas e pilastras.",
                    0,
                    $e
                );
            }

            return $resultIdentities;
        }

        /**
         * Esse método tenta garantir que apenas um registro seja
         * retornado no conjunto de resultados.
         *
         * @param  array $resultIdentities.
         * @return bool|AuthenticationResult.
         */
        protected function authenticateValidateResultSet(array $resultIdentities)
        {
            if (!$resultIdentities)
            {
                $this->authenticateResultInfo["code"] = AuthenticationResult::FAILURE_IDENTITY_NOT_FOUND;
                $this->authenticateResultInfo["messages"][] = "Não foi possível encontrar um registro com a identificação fornecida.";

                return $this->authenticateCreateAuthResult();
            } elseif (count($resultIdentities) > 1 && false === $this->getAmbiguityIdentity())
            {
                $this->authenticateResultInfo["code"] = AuthenticationResult::FAILURE_IDENTITY_AMBIGUOUS;
                $this->authenticateResultInfo["messages"][] = "Mais de um registro corresponde à identificação fornecida.";

                return $this->authenticateCreateAuthResult();
            }

            return true;
        }

        /**
         * Cria um objeto Laminas\Authentication\Result a partir das
         * informações obtidas durante a tentativa de authenticate().
         *
         * @return AuthenticationResult.
         */
        protected function authenticateCreateAuthResult()
        {
            return new AuthenticationResult(
                $this->authenticateResultInfo["code"],
                $this->authenticateResultInfo["identity"],
                $this->authenticateResultInfo["messages"]
            );
        }
    }
