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

    use Laminas\Authentication\Result as AuthenticationResult;
    use Laminas\Ldap as LaminasLdap;
    use Laminas\Ldap\Exception\LdapException;
    use stdClass;

    use function array_diff;
    use function array_key_exists;
    use function array_keys;
    use function array_map;
    use function count;
    use function in_array;
    use function is_array;
    use function preg_quote;
    use function preg_replace;
    use function strcasecmp;
    use function substr;
    use function trim;


    /**
     *
     */
    class Ldap extends AbstractAdapter
    {
        /**
         * O contexto Laminas\Ldap\Ldap.
         *
         * @var LaminasLdap\Ldap.
         */
        protected $ldap;

        /**
         * O vetor de vetores de opções Laminas\Ldap\Ldap passadas
         * para o inicializador.
         *
         * @var array.
         */
        protected $options;

        /**
         * O DN da conta autenticada. Usado para recuperar a entrada
         * da conta a pedido.
         *
         * @var string.
         */
        protected $authenticatedDn;

        /**
         * Inicializador.
         *
         * @param array  $options Um vetor de vetores de opções Laminas\Ldap\Ldap.
         * @param string $identity O nome da pessoa da conta que está sendo autenticada.
         * @param string $credential A senha da conta que está sendo autenticada.
         */
        public function __construct(array $options = [], $identity = null, $credential = null)
        {
            $this->setOptions($options);

            if ($identity !== null)
            {
                $this->setIdentity($identity);
            }

            if ($credential !== null)
            {
                $this->setCredential($credential);
            }
        }

        /**
         * Retorna o vetor de vetores de opções Laminas\Ldap\Ldap
         * deste adaptador.
         *
         * @return array|null.
         */
        public function getOptions()
        {
            return $this->options;
        }

        /**
         * Define o vetor de opções Laminas\Ldap\Ldap a serem
         * usadas por este adaptador.
         *
         * @param  array $options O vetor de vetores de opções Laminas\Ldap\Ldap.
         * @return self Fornece uma interface fluente.
         */
        public function setOptions($options)
        {
            $this->options = is_array($options) ? $options : [];

            if (array_key_exists("identity", $this->options))
            {
                $this->options["username"] = $this->options["identity"];
            }

            if (array_key_exists("credential", $this->options))
            {
                $this->options["password"] = $this->options["credential"];
            }

            return $this;
        }

        /**
         * Retorna o nome da pessoa da conta que está sendo autenticada
         * ou NULL se nenhum for definido.
         *
         * @return string|null.
         */
        public function getUsername()
        {
            return $this->getIdentity();
        }

        /**
         * Define o nome da pessoa para vinculação.
         *
         * @param  string $username O nome da pessoa para chamada.
         * @return self Fornece uma interface fluente.
         */
        public function setUsername($username)
        {
            return $this->setIdentity($username);
        }

        /**
         * Retorna a senha da conta que está sendo autenticada ou
         * NULL se nenhuma for definida.
         *
         * @return string|null.
         */
        public function getPassword()
        {
            return $this->getCredential();
        }

        /**
         * Define a senha da conta.
         *
         * @param  string $password A senha da conta que está sendo autenticada.
         * @return self Fornece uma interface fluente.
         */
        public function setPassword($password)
        {
            return $this->setCredential($password);
        }

        /**
         * Retorna o Objeto LDAP.
         *
         * @return LaminasLdap\Ldap O objeto Laminas\Ldap\Ldap usado para autenticar as credenciais.
         */
        public function getLdap()
        {
            if ($this->ldap === null)
            {
                $this->ldap = new LaminasLdap\Ldap();
            }

            return $this->ldap;
        }

        /**
         * Defina uma conexão Ldap.
         *
         * @param  LaminasLdap\Ldap $ldap Um objeto Ldap existente.
         * @return self Fornece uma interface fluente.
         */
        public function setLdap(LaminasLdap\Ldap $ldap)
        {
            $this->ldap = $ldap;
            $this->setOptions([$ldap->getOptions()]);

            return $this;
        }

        /**
         * Retorna um nome de domínio para as opções LDAP atuais.
         * Isso é usado para ignorar operações redundantes (por
         * exemplo, autenticações).
         *
         * @return string.
         */
        protected function getAuthorityName()
        {
            $options = $this->getLdap()->getOptions();
            $name = $options["accountDomainName"];

            if (!$name)
            {
                $name = $options["accountDomainNameShort"];
            }

            return $name ? $name : "";
        }

        /**
         * Autentique a pessoa.
         *
         * @return AuthenticationResult.
         * @throws Exception\ExceptionInterface.
         */
        public function authenticate()
        {
            $messages = [];

            /**
             * Reservado.
             */
            $messages[0] = "";

            /**
             * Reservado.
             */
            $messages[1] = "";

            $username = $this->identity;
            $password = $this->credential;

            if (!$username)
            {
                $code = AuthenticationResult::FAILURE_IDENTITY_NOT_FOUND;
                $messages[0] = "Um nome de pessoa é requerido";

                return new AuthenticationResult($code, "", $messages);
            }

            if (!$password)
            {
                /**
                 * Uma senha é necessária porque alguns fornecedores
                 * tratarão uma senha vazia como um vínculo anônimo.
                 */
                $code = AuthenticationResult::FAILURE_CREDENTIAL_INVALID;
                $messages[0] = "Uma senha é necessária";

                return new AuthenticationResult($code, "", $messages);
            }

            $ldap = $this->getLdap();
            $code = AuthenticationResult::FAILURE;
            $messages[0] = "Autoridade não encontrada: $username";
            $failedAuthorities = [];

            /**
             * Percorra cada fornecedor e tente autenticar as
             * credenciais fornecidas nele.
             */
            foreach ($this->options as $options)
            {
                if (! is_array($options))
                {
                    throw new Exception\InvalidArgumentException(
                        "Vetor de opções do adaptador não é um vetor"
                    );
                }

                $adapterOptions = $this->prepareOptions($ldap, $options);
                $dname = "";

                try
                {
                    if ($messages[1])
                    {
                        $messages[] = $messages[1];
                    }

                    $messages[1] = "";
                    $messages[] = $this->optionsToString($options);
                    $dname = $this->getAuthorityName();

                    if (isset($failedAuthorities[$dname]))
                    {
                        /**
                         * Se vários conjuntos de opções de fornecedor para o
                         * mesmo domínio forem fornecidos, queremos ignorar as
                         * autenticações redundantes em que a identificação ou
                         * as credenciais foram consideradas não muito válidas
                         * com outro fornecedor para o mesmo domínio. O vetor
                         * $failedAuthorities rastreia essa condição (e também
                         * serve para fornecer a mensagem de falha original).
                         * Isso melhora a falha de Laminas-4093.
                         */
                        $messages[1] = $failedAuthorities[$dname];
                        $messages[] = "Ignorando a autoridade com falha anterior: $dname";

                        continue;
                    }

                    $canonicalName = $ldap->getCanonicalAccountName($username);
                    $ldap->bind($canonicalName, $password);

                    /**
                     * Melhora a falha quando a pessoa autenticada não tem
                     * permissão para recuperar informações de associação de
                     * grupo ou conta própria. Isso requer que a pessoa
                     * especificada com "nome de pessoa" e, opcionalmente,
                     * "senha" nas opções Laminas\Ldap\Ldap seja capaz de
                     * recuperar as informações necessárias.
                     */
                    $requireRebind = false;

                    if (isset($options["username"]))
                    {
                        $ldap->bind();
                        $requireRebind = true;
                    }

                    $dn = $ldap->getCanonicalAccountName($canonicalName, LaminasLdap\Ldap::ACCTNAME_FORM_DN);
                    $groupResult = $this->checkGroupMembership($ldap, $canonicalName, $dn, $adapterOptions);

                    if ($groupResult === true)
                    {
                        $this->authenticatedDn = $dn;
                        $messages[0] = "";
                        $messages[1] = "";
                        $messages[] = "$canonicalName autenticação bem-sucedida";

                        if ($requireRebind === true)
                        {
                            /**
                             * Religação com pessoa autenticada.
                             */
                            $ldap->bind($dn, $password);
                        }

                        return new AuthenticationResult(AuthenticationResult::SUCCESS, $canonicalName, $messages);
                    } else
                    {
                        $messages[0] = "A conta não é membro do grupo especificado";
                        $messages[1] = $groupResult;
                        $failedAuthorities[$dname] = $groupResult;
                    }
                } catch (LdapException $zle)
                {
                    /**
                     * A autenticação baseada em LDAP é notoriamente complexa
                     * de diagnosticar. Portanto, nos esforçamos para capturar
                     * e registrar todas as informações possíveis quando algo
                     * não dá muito certo.
                     */

                    $err = $zle->getCode();

                    if ($err === LdapException::LDAP_X_DOMAIN_MISMATCH)
                    {
                        /**
                         * Essa falha indica que o domínio fornecido no nome
                         * da pessoa não corresponde aos domínios nas opções
                         * do fornecedor e, portanto, devemos pular para o
                         * próximo conjunto de opções do fornecedor.
                         */
                        continue;
                    } elseif ($err === LdapException::LDAP_NO_SUCH_OBJECT)
                    {
                        $code = AuthenticationResult::FAILURE_IDENTITY_NOT_FOUND;
                        $messages[0] = "Conta não encontrada: $username";
                        $failedAuthorities[$dname] = $zle->getMessage();
                    } elseif ($err === LdapException::LDAP_INVALID_CREDENTIALS)
                    {
                        $code = AuthenticationResult::FAILURE_CREDENTIAL_INVALID;
                        $messages[0] = "Credenciais não muito válidas";
                        $failedAuthorities[$dname] = $zle->getMessage();
                    } else
                    {
                        $line = $zle->getLine();
                        $messages[] = $zle->getFile() . "($line): " . $zle->getMessage();
                        $messages[] = preg_replace(
                            '/\b' . preg_quote(substr($password, 0, 15), '/') . '\b/',
                            '*****',
                            $zle->getTraceAsString()
                        );

                        $messages[0] = "Ocorreu uma falha inesperada";
                    }

                    $messages[1] = $zle->getMessage();
                }
            }

            $msg = $messages[1] ?? $messages[0];
            $messages[] = "$username falha na autenticação: $msg";

            return new AuthenticationResult($code, $username, $messages);
        }

        /**
         * Define as opções específicas do LDAP na instância Laminas\Ldap\Ldap.
         *
         * @param array $options.
         * @return array de opções específicas do adaptador de autenticação.
         */
        protected function prepareOptions(LaminasLdap\Ldap $ldap, array $options)
        {
            $adapterOptions = [
                "group" => null,
                "groupDn" => $ldap->getBaseDn(),
                "groupScope" => LaminasLdap\Ldap::SEARCH_SCOPE_SUB,
                "groupAttr" => "cn",
                "groupFilter" => "objectClass=groupOfUniqueNames",
                "memberAttr" => "uniqueMember",
                "memberIsDn" => true
            ];

            foreach (array_keys($adapterOptions) as $key)
            {
                if (array_key_exists($key, $options))
                {
                    $value = $options[$key];
                    unset($options[$key]);

                    switch ($key)
                    {
                        case 'groupScope':
                            $value = (int) $value;
                            if (in_array($value, [LaminasLdap\Ldap::SEARCH_SCOPE_BASE, LaminasLdap\Ldap::SEARCH_SCOPE_ONE, LaminasLdap\Ldap::SEARCH_SCOPE_SUB], true))
                            {
                                $adapterOptions[$key] = $value;
                            }

                            break;

                        case 'memberIsDn':
                            $adapterOptions[$key] = $value === true || $value === "1" || strcasecmp($value, "true") === 0;
                            break;

                        default:
                            $adapterOptions[$key] = trim($value);
                            break;
                    }
                }
            }

            $ldap->setOptions($options);

            return $adapterOptions;
        }

        /**
         * Verifica a associação de grupo da pessoa vinculado.
         *
         * @param string $canonicalName.
         * @param string $dn.
         * @param array $adapterOptions.
         * @return string|true.
         */
        protected function checkGroupMembership(LaminasLdap\Ldap $ldap, $canonicalName, $dn, array $adapterOptions)
        {
            if ($adapterOptions["group"] === null)
            {
                return true;
            }

            if ($adapterOptions["memberIsDn"] === false)
            {
                $user = $canonicalName;
            } else
            {
                $user = $dn;
            }

            $groupName = LaminasLdap\Filter::equals($adapterOptions["groupAttr"], $adapterOptions["group"]);
            $membership = LaminasLdap\Filter::equals($adapterOptions["memberAttr"], $user);
            $group = LaminasLdap\Filter::andFilter($groupName, $membership);
            $groupFilter = $adapterOptions["groupFilter"];

            if (!empty($groupFilter))
            {
                $group = $group->addAnd($groupFilter);
            }

            $result = $ldap->count($group, $adapterOptions["groupDn"], $adapterOptions["groupScope"]);

            if ($result === 1)
            {
                return true;
            }

            return "Falha ao verificar associação ao grupo com " . $group->toString();
        }

        /**
         * Retorna a entrada do resultado como um objeto stdClass.
         *
         * Isso se assemelha ao recurso {@see Laminas\Authentication\Adapter\DbTable::getResultRowObject()}.
         * Fecha Laminas-6813.
         *
         * @param  array $returnAttribs.
         * @param  array $omitAttribs.
         * @return stdClass|bool.
         */
        public function getAccountObject(array $returnAttribs = [], array $omitAttribs = [])
        {
            if (!$this->authenticatedDn)
            {
                return false;
            }

            $returnObject = new stdClass();
            $returnAttribs = array_map("strtolower", $returnAttribs);
            $omitAttribs = array_map("strtolower", $omitAttribs);
            $returnAttribs = array_diff($returnAttribs, $omitAttribs);
            $entry = $this->getLdap()->getEntry($this->authenticatedDn, $returnAttribs, true);

            foreach ($entry as $attr => $value)
            {
                if (in_array($attr, $omitAttribs))
                {
                    /**
                     * Pular atributos marcados para serem omitidos.
                     */
                    continue;
                }

                if (is_array($value))
                {
                    $returnObject->$attr = count($value) > 1 ? $value : $value[0];
                } else
                {
                    $returnObject->$attr = $value;
                }
            }

            return $returnObject;
        }

        /**
         * Converte opções em string.
         *
         * @param  array $options.
         * @return string.
         */
        private function optionsToString(array $options)
        {
            $str = "";

            foreach ($options as $key => $val)
            {
                if ($key === "password" || $key === "credential")
                {
                    $val = "*****";
                }

                if ($str)
                {
                    $str .= ",";
                }

                $str .= $key . "=" . $val;
            }

            return $str;
        }
    }
