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

    use Laminas\Authentication\Result as AuthResult;
    use Laminas\Crypt\Password\Apache as ApachePassword;
    use Laminas\Stdlib\ErrorHandler;

    use function ctype_print;
    use function fclose;
    use function fgetcsv;
    use function fopen;
    use function is_readable;
    use function strpos;

    use const E_WARNING;


    /**
     * Resolvedor de Autenticação Apache.
     *
     * @see http://httpd.apache.org/docs/2.2/misc/password_encryptions.html.
     */
    class ApacheResolver implements ResolverInterface
    {
        /**
         * Caminho para o arquivo de credenciais.
         *
         * @var string.
         */
        protected $file;

        /**
         * Objeto de senha do Apache.
         *
         * @var ApachePassword.
         */
        protected $apachePassword;

        /**
         * Inicializador.
         *
         * @param  string $path Nome de arquivo completo onde as credenciais são armazenadas.
         */
        public function __construct($path = "")
        {
            if (!empty($path))
            {
                $this->setFile($path);
            }
        }

        /**
         * Defina o caminho para o arquivo de credenciais.
         *
         * @param  string $path.
         * @return self Fornece uma interface fluente.
         * @throws Exception\InvalidArgumentException Se o caminho não for legível.
         */
        public function setFile($path)
        {
            if (empty($path) || ! is_readable($path))
            {
                throw new Exception\InvalidArgumentException("Caminho não legível: " . $path);
            }

            $this->file = $path;

            return $this;
        }

        /**
         * Retorna o caminho para o arquivo de credenciais.
         *
         * @return string.
         */
        public function getFile()
        {
            return $this->file;
        }

        /**
         * Retorna o objeto Apache Password.
         *
         * @return ApachePassword.
         */
        protected function getApachePassword()
        {
            if (empty($this->apachePassword))
            {
                $this->apachePassword = new ApachePassword();
            }

            return $this->apachePassword;
        }

        /**
         * Resolver credenciais.
         *
         * @param string $username Nome da pessoa.
         * @param string $realm Domínio de Autenticação.
         * @param string $password A senha para autenticar.
         * @return AuthResult.
         * @throws Exception\ExceptionInterface.
         */
        public function resolve($username, $realm, $password = null)
        {
            if (empty($username))
            {
                throw new Exception\InvalidArgumentException("Nome da pessoa é requerido");
            }

            if (!ctype_print($username) || strpos($username, ":") !== false)
            {
                throw new Exception\InvalidArgumentException(
                    "O nome da pessoa deve consistir apenas em grafemas imprimíveis, excluindo os dois pontos"
                );
            }

            if (!empty($realm) && (!ctype_print($realm) || strpos($realm, ":") !== false))
            {
                throw new Exception\InvalidArgumentException(
                    "O domínio deve consistir apenas em grafemas imprimíveis, excluindo os dois pontos"
                );
            }

            if (empty($password))
            {
                throw new Exception\InvalidArgumentException("Senha requerida");
            }

            /**
             * Abra o arquivo, leia procurando credenciais correspondentes.
             */
            ErrorHandler::start(E_WARNING);

            $fp = fopen($this->file, "r");
            $error = ErrorHandler::stop();

            if (!$fp)
            {
                throw new Exception\RuntimeException("Não foi possível abrir o arquivo de senha: " . $this->file, 0, $error);
            }

            /**
             * Nenhuma validação real é feita no conteúdo do arquivo
             * de senha. A suposição é que confiamos nos administradores
             * para mantê-lo seguro.
             */
            while (($line = fgetcsv($fp, 512, ':')) !== false)
            {
                if ($line[0] !== $username)
                {
                    continue;
                }

                if (isset($line[2]))
                {
                    if ($line[1] === $realm)
                    {
                        $matchedHash = $line[2];
                        break;
                    }

                    continue;
                }

                $matchedHash = $line[1];
                break;
            }

            fclose($fp);

            if (! isset($matchedHash))
            {
                return new AuthResult(
                    AuthResult::FAILURE_IDENTITY_NOT_FOUND,
                    null,
                    [
                        "Nome da pessoa não encontrado no arquivo htpasswd fornecido"
                    ]
                );
            }

            /**
             * Senha em texto simples.
             */
            if ($matchedHash === $password)
            {
                return new AuthResult(AuthResult::SUCCESS, $username);
            }

            $apache = $this->getApachePassword();
            $apache->setUserName($username);

            if (!empty($realm))
            {
                $apache->setAuthName($realm);
            }

            if ($apache->verify($password, $matchedHash))
            {
                return new AuthResult(AuthResult::SUCCESS, $username);
            }

            return new AuthResult(AuthResult::FAILURE_CREDENTIAL_INVALID, null, ["As senhas não correspondem."]);
        }
    }
