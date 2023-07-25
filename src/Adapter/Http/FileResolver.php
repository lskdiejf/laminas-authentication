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

    use Laminas\Stdlib\ErrorHandler;

    use function ctype_print;
    use function fclose;
    use function fgetcsv;
    use function fopen;
    use function is_readable;
    use function strpos;

    use const E_WARNING;

    /**
     * Resolvedor de arquivo de autenticação HTTP.
     */
    class FileResolver implements ResolverInterface
    {
        /**
         * Caminho para o arquivo de credenciais.
         *
         * @var string.
         */
        protected $file;

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
         * @return string
         */
        public function getFile()
        {
            return $this->file;
        }

        /**
         * Resolver credenciais.
         *
         * Somente a primeira combinação de nome de pessoa/domínio
         * correspondente no arquivo é retornada. Se o arquivo contiver
         * credenciais para autenticação Digest, a string retornada é o
         * hash de senha ou h(a1) de RFC 2617. A string retornada é a
         * senha de texto sem formatação para autenticação básica.
         *
         * O formato esperado do arquivo é:
         *     username:realm:sharedSecret
         *
         * Ou seja, cada linha consiste no nome de pessoa da pessoa,
         * o domínio de autenticação aplicável e a senha ou hash,
         * cada um delimitado por dois pontos.
         *
         * @param  string $username Nome da pessoa.
         * @param  string $realm Domínio de Autenticação.
         * @param string|null $password.
         * @return string|false Segredo compartilhado da pessoa, se a pessoa
         *                      for encontrado no domínio, falso caso contrário.
         * @throws Exception\ExceptionInterface.
         */
        public function resolve($username, $realm, $password = null)
        {
            if (empty($username))
            {
                throw new Exception\InvalidArgumentException("Nome da pessoa é requerido");
            } elseif (!ctype_print($username) || strpos($username, ":") !== false)
            {
                throw new Exception\InvalidArgumentException(
                    "O nome da pessoa deve consistir apenas em grafemas " .
                    "imprimíveis, excluindo os dois pontos"
                );
            }

            if (empty($realm))
            {
                throw new Exception\InvalidArgumentException("O domínio é obrigatório");
            } elseif (!ctype_print($realm) || strpos($realm, ":") !== false)
            {
                throw new Exception\InvalidArgumentException(
                    "O domínio deve consistir apenas em grafemas " .
                    "imprimíveis, excluindo os dois pontos."
                );
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
            while (($line = fgetcsv($fp, 512, ":", "\"")) !== false)
            {
                if ($line[0] === $username && $line[1] === $realm)
                {
                    $password = $line[2];
                    fclose($fp);

                    return $password;
                }
            }

            fclose($fp);

            return false;
        }
    }
