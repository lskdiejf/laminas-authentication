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

    use Laminas\Authentication;
    use Laminas\Crypt\Utils as CryptUtils;
    use Laminas\Http\Request as HTTPRequest;
    use Laminas\Http\Response as HTTPResponse;
    use Laminas\Uri\UriFactory;

    use function array_intersect;
    use function base64_decode;
    use function ceil;
    use function ctype_print;
    use function ctype_xdigit;
    use function explode;
    use function hash;
    use function implode;
    use function in_array;
    use function is_array;
    use function is_numeric;
    use function preg_match;
    use function sprintf;
    use function strlen;
    use function strpos;
    use function strtolower;
    use function substr;
    use function time;
    use function trigger_error;

    use const E_USER_DEPRECATED;


    /**
     * Adaptador de autenticação HTTP.
     *
     * Implementa uma boa seção do RFC 2617.
     *
     * @todo Suporta auth-int.
     * @todo Rastreie nonces, nonce-count, opaco para proteção de replay e suporte que não está mais em uso.
     * @todo Suporta Authentication-Info header.
     */
    class Http implements AdapterInterface
    {
        /**
         * Referência ao objeto Solicitação HTTP.
         *
         * @var HTTPRequest.
         */
        protected $request;

        /**
         * Referência ao objeto de resposta HTTP.
         *
         * @var HTTPResponse.
         */
        protected $response;

        /**
         * Objeto que procura as credenciais da pessoa para
         * o esquema Básico.
         *
         * @var Http\ResolverInterface.
         */
        protected $basicResolver;

        /**
         * Objeto que procura as credenciais da pessoa para o esquema Digest.
         *
         * @var Http\ResolverInterface.
         */
        protected $digestResolver;

        /**
         * Lista de esquemas de autenticação suportados por esta classe.
         *
         * @var string[].
         */
        protected $supportedSchemes = ['basic', 'digest'];

        /**
         * Lista de esquemas que esta classe aceitará do cliente.
         *
         * @var array.
         */
        protected $acceptSchemes;

        /**
         * Lista delimitada por espaço de domínios protegidos
         * para Digest Auth.
         *
         * @var string.
         */
        protected $domains;

        /**
         * O domínio de proteção a ser usado.
         *
         * @var string.
         */
        protected $realm;

        /**
         * Nonce período de tempo limite.
         *
         * @var int.
         */
        protected $nonceTimeout;

        /**
         * Se o valor opaco deve ser enviado no título.
         * Normalmente verdadeiro.
         *
         * @var bool.
         */
        protected $useOpaque;

        /**
         * Lista dos algoritmos de compilação suportados. Eu quero
         * suportar tanto o MD5 quanto o MD5-sess, mas o MD5-sess
         * não entrará na primeira versão.
         *
         * @var string[].
         */
        protected $supportedAlgos = ["MD5"];

        /**
         * O algoritmo real a ser usado. Normalmente é MD5.
         *
         * @var string.
         */
        protected $algo;

        /**
         * Lista de opções qop suportadas. Minha intenção é oferecer
         * suporte a 'auth' e 'auth-int', mas 'auth-int' não entrará
         * na primeira versão.
         *
         * @var string[].
         */
        protected $supportedQops = ['auth'];

        /**
         * Se deve ou não fazer autenticação de proxy em vez de
         * autenticação de fornecedor de origem (enviar 407 em
         * vez de 401). Normalmente é ['Off'].
         *
         * @var bool.
         */
        protected $imaProxy = false;

        /**
         * Sinalizador indicando que o cliente é IE e não se preocupou
         * em retornar a string opaca.
         *
         * @var bool.
         */
        protected $ieNoOpaque = false;

        /**
         * Inicialização.
         *
         * @param vetor $config Definições de configuração:
         *     'accept_schemes' => 'basic'|'digest'|'basic digest'.
         *     'realm' => <string>.
         *     'digest_domains' => <string> Lista de URIs delimitada por espaço.
         *     'nonce_timeout' => <int>.
         *     'use_opaque' => <bool> Se deve enviar o valor opaco no título.
         *     'algorithm' => <string> Consulte $supportedAlgos. Normalmente é: MD5.
         *     'proxy_auth' => <bool> Se deve fazer a autenticação como um Proxy.
         *
         * @throws Exception\InvalidArgumentException.
         */
        public function __construct(array $config)
        {
            if (empty($config['accept_schemes']))
            {
                throw new Exception\InvalidArgumentException("Chave de configuração \"accept_schemes\" é necessário");
            }

            $schemes = explode(" ", $config["accept_schemes"]);
            $this->acceptSchemes = array_intersect($schemes, $this->supportedSchemes);

            if (empty($this->acceptSchemes))
            {
                throw new Exception\InvalidArgumentException(sprintf(
                    "Nenhum esquema suportado fornecido em \"accept_schemes\". Valores válidos: %s",
                    implode(', ', $this->supportedSchemes)
                ));
            }

            /**
             * As aspas duplas são usadas para delimitar a sequência
             * de domínio no título HTTP e os dois-pontos são delimitadores
             * de campo no arquivo de senha.
             */
            if (empty($config["realm"]) || !ctype_print($config["realm"]) || strpos($config["realm"], ":") !== false || strpos($config["realm"], "\"") !== false
            )
            {
                throw new Exception\InvalidArgumentException(
                    "Chave de configuração 'realm' é obrigatório e deve " .
                    "conter apenas grafemas imprimíveis, excluindo aspas e " .
                    "dois-pontos"
                );
            } else
            {
                $this->realm = $config["realm"];
            }

            if (in_array("digest", $this->acceptSchemes))
            {
                $this->useOpaque = true;
                $this->algo = "MD5";

                if (empty($config["digest_domains"]) || !ctype_print($config["digest_domains"]) || strpos($config["digest_domains"], "\"") !== false)
                {
                    throw new Exception\InvalidArgumentException(
                        "Chave de configuração 'digest_domains' é obrigatório " .
                        "e deve conter apenas grafemas imprimíveis, excluindo aspas"
                    );
                } else
                {
                    $this->domains = $config["digest_domains"];
                }

                if (empty($config["nonce_timeout"]) || !is_numeric($config["nonce_timeout"])
                ) {
                    throw new Exception\InvalidArgumentException(
                        "Chave de configuração 'nonce_timeout' é obrigatório e " .
                        "deve ser um número inteiro"
                    );
                } else
                {
                    $this->nonceTimeout = (int) $config["nonce_timeout"];
                }

                /**
                 * Usamos o valor opaco, a menos que seja explicitamente
                 * instruído a não fazê-lo.
                 */
                if (isset($config["use_opaque"]) && false === (bool) $config["use_opaque"])
                {
                    $this->useOpaque = false;
                }

                if (isset($config["algorithm"]) && in_array($config["algorithm"], $this->supportedAlgos))
                {
                    $this->algo = (string) $config["algorithm"];
                }
            }

            /**
             * Não seja um proxy, a menos que seja explicitamente
             * instruído a fazê-lo.
             */
            if (isset($config["proxy_auth"]) && true === (bool) $config["proxy_auth"])
            {
                /**
                 * Eu sou um rastreamento.
                 */
                $this->imaProxy = true;
            }
        }

        /**
         * Setter para a propriedade basicResolver.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setBasicResolver(Http\ResolverInterface $resolver)
        {
            $this->basicResolver = $resolver;

            return $this;
        }

        /**
         * Getter para a propriedade basicResolver.
         *
         * @return Http\ResolverInterface.
         */
        public function getBasicResolver()
        {
            return $this->basicResolver;
        }

        /**
         * Setter para a propriedade digestResolver.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setDigestResolver(Http\ResolverInterface $resolver)
        {
            $this->digestResolver = $resolver;

            return $this;
        }

        /**
         * Getter para a propriedade digestResolver.
         *
         * @return Http\ResolverInterface.
         */
        public function getDigestResolver()
        {
            return $this->digestResolver;
        }

        /**
         * Setter para o objeto Request.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setRequest(HTTPRequest $request)
        {
            $this->request = $request;

            return $this;
        }

        /**
         * Getter para o objeto Request.
         *
         * @return HTTPRequest.
         */
        public function getRequest()
        {
            return $this->request;
        }

        /**
         * Setter para o objeto Response.
         *
         * @return self Fornece uma interface fluente.
         */
        public function setResponse(HTTPResponse $response)
        {
            $this->response = $response;

            return $this;
        }

        /**
         * Getter para o objeto Response.
         *
         * @return HTTPResponse.
         */
        public function getResponse()
        {
            return $this->response;
        }

        /**
         * Autenticar.
         *
         * @throws Exception\RuntimeException.
         * @return Authentication\Result.
         */
        public function authenticate()
        {
            if (empty($this->request) || empty($this->response))
            {
                throw new Exception\RuntimeException(
                    "Os objetos Request e Response devem ser definidos " .
                    "antes da chamada authenticate()"
                );
            }

            if ($this->imaProxy)
            {
                $getHeader = 'Proxy-Authorization';
            } else
            {
                $getHeader = 'Authorization';
            }

            $headers = $this->request->getHeaders();

            if (!$headers->has($getHeader))
            {
                return $this->challengeClient();
            }

            $authHeader = $headers->get($getHeader)->getFieldValue();

            if (!$authHeader)
            {
                return $this->challengeClient();
            }

            [$clientScheme] = explode(" ", $authHeader);
            $clientScheme = strtolower($clientScheme);

            /**
             * O fornecedor pode emitir vários desafios, mas o cliente
             * deve responder apenas com o esquema de autenticação
             * selecionado.
             */
            if (!in_array($clientScheme, $this->supportedSchemes))
            {
                $this->response->setStatusCode(400);

                return new Authentication\Result(
                    Authentication\Result::FAILURE_UNCATEGORIZED,
                    [],
                    [
                        "O cliente solicitou um esquema de autenticação incorreto ou sem suporte"
                    ]
                );
            }

            /**
             * O cliente enviou um esquema que não é o requerido.
             */
            if (! in_array($clientScheme, $this->acceptSchemes))
            {
                /**
                 * Chamada novamente para o cliente.
                 */
                return $this->challengeClient();
            }

            switch ($clientScheme)
            {
                case 'basic':
                    $result = $this->_basicAuth($authHeader);
                    break;

                case 'digest':
                    $result = $this->_digestAuth($authHeader);
                    break;

                default:
                    throw new Exception\RuntimeException("Esquema de autenticação não suportado: " . $clientScheme);
            }

            return $result;
        }

        /**
         * @see Http::challengeClient().
         *
         * @return Authentication\Result Sempre retorna um resultado Auth sem identificação.
         * @codingStandardsIgnoreStart.
         */
        protected function _challengeClient()
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            trigger_error(sprintf(
                "O método "%s" não está mais em uso e será removido no futuro; " .
                "por favor, use o método público \"%s::challengeClient()\" " .
                "em vez desse",
                __METHOD__,
                self::class
            ), E_USER_DEPRECATED);

            return $this->challengeClient();
        }

        /**
         * Pessoa.
         *
         * Define um código de resposta não autorizado 401 ou 407 e
         * cria o(s) título(s) de autenticação apropriado(s) para
         * solicitar credenciais.
         *
         * @return Authentication\Result Sempre retorna um resultado Auth sem identificação.
         */
        public function challengeClient()
        {
            if ($this->imaProxy)
            {
                $statusCode = 407;
                $headerName = "Proxy-Authenticate";
            } else
            {
                $statusCode = 401;
                $headerName = "WWW-Authenticate";
            }

            $this->response->setStatusCode($statusCode);

            /**
             * Envie um desafio em cada esquema de autenticação aceitável.
             */
            $headers = $this->response->getHeaders();

            if (in_array("basic", $this->acceptSchemes))
            {
                $headers->addHeaderLine($headerName, $this->_basicHeader());
            }

            if (in_array("digest", $this->acceptSchemes))
            {
                $headers->addHeaderLine($headerName, $this->_digestHeader());
            }

            return new Authentication\Result(
                Authentication\Result::FAILURE_CREDENTIAL_INVALID,
                [],
                ["Credenciais inválidas ou ausentes; pessoa fazendo uma conexão"]
            );
        }

        /**
         * Título Básico.
         *
         * Gera um valor de título Proxy- ou WWW-Authenticate no
         * esquema de autenticação básica.
         *
         * @return string Autenticar o valor do título.
         * @codingStandardsIgnoreStart.
         */
        protected function _basicHeader()
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            return "Basic realm=\"" . $this->realm . "\"";
        }

        /**
         * Resumo do título.
         *
         * Gera um valor de título Proxy- ou WWW-Authenticate no
         * esquema de autenticação Digest.
         *
         * @return string Autenticar o valor do título.
         * @codingStandardsIgnoreStart.
         */
        protected function _digestHeader()
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            return "Digest realm=\"" . $this->realm . "\", " .
                "domain=\"" . $this->domains . "\", " .
                "nonce=\"" . $this->_calcNonce() . "\", " .
                ($this->useOpaque ? "opaque=\"" . $this->_calcOpaque() . "\", " : "") .
                "algorithm=\"" . $this->algo . "\", " .
                "qop=\"" . implode(",", $this->supportedQops) . "\"";
        }

        /**
         * Autenticação básica.
         *
         * @param  string $header Título de autorização do cliente.
         * @throws Exception\ExceptionInterface.
         * @return Authentication\Result.
         * @codingStandardsIgnoreStart.
         */
        protected function _basicAuth($header)
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            if (empty($header))
            {
                throw new Exception\RuntimeException(
                    "O valor do título de autorização do cliente é obrigatório"
                );
            }

            if (empty($this->basicResolver)) {
                throw new Exception\RuntimeException(
                    "Um objeto basicResolver deve ser definido antes de " .
                    "fazer a autenticação básica"
                );
            }

            /**
             * Decodifique o título de autorização.
             */
            $auth = substr($header, strlen("Basic "));
            if ($auth === false)
            {
                return $this->challengeClient();
            }

            $auth = base64_decode($auth);
            if (!$auth)
            {
                return $this->challengeClient();
            }

            /**
             * Consulte Laminas-1253. Valide as credenciais da mesma
             * forma que a implementação do resumo. Se forem detectadas
             * credenciais não muito válidas, faça uma chamada novamente
             * para o cliente.
             */
            if (!ctype_print($auth))
            {
                return $this->challengeClient();
            }

            $pos = strpos($auth, ":");
            if ($pos === false)
            {
                return $this->challengeClient();
            }

            [
                $username,
                $password
            ] = explode(":", $auth, 2);

            /**
             * Melhoria para Laminas-1515: Agora, novas chamadas em
             * nome de pessoas ou senha vazias.
             */
            if (empty($username) || empty($password))
            {
                return $this->challengeClient();
            }

            $result = $this->basicResolver->resolve($username, $this->realm, $password);

            if ($result instanceof Authentication\Result && $result->isValid())
            {
                return $result;
            }

            if (!$result instanceof Authentication\Result && ! is_array($result) && CryptUtils::compareStrings($result, $password))
            {
                $identity = [
                    "username" => $username,
                    "realm" => $this->realm
                ];

                return new Authentication\Result(Authentication\Result::SUCCESS, $identity);
            } elseif (is_array($result))
            {
                return new Authentication\Result(Authentication\Result::SUCCESS, $result);
            }

            return $this->challengeClient();
        }

        /**
         * Autenticação resumida.
         *
         * @param  string $header Título de autorização do cliente.
         * @throws Exception\ExceptionInterface.
         * @return Authentication\Result Resultado de autenticação válido somente em autenticação bem-sucedida.
         * @codingStandardsIgnoreStart.
         */
        protected function _digestAuth($header)
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            if (empty($header))
            {
                throw new Exception\RuntimeException(
                    "O valor do título de autorização do cliente é obrigatório"
                );
            }

            if (empty($this->digestResolver)) {
                throw new Exception\RuntimeException(
                    "Um objeto digestResolver deve ser definido antes de fazer " .
                    "a autenticação Digest"
                );
            }

            $data = $this->_parseDigestAuth($header);
            if ($data === false)
            {
                $this->response->setStatusCode(400);
                return new Authentication\Result(
                    Authentication\Result::FAILURE_UNCATEGORIZED,
                    [],
                    ["Formato de título de autorização não muito válido"]
                );
            }

            /**
             * Consulte Laminas-1052. Este código era um pouco implacável
             * com nomes de objetos não muito válidos. Agora, se o nome
             * da pessoa for incorreto, fazemos uma nova ligação para o
             * cliente.
             */
            if ("::invalid::" === $data["username"])
            {
                return $this->challengeClient();
            }

            /**
             * Verifique se o cliente enviou de volta o mesmo nonce.
             */
            if ($this->_calcNonce() !== $data["nonce"])
            {
                return $this->challengeClient();
            }

            /**
             * O valor opaco também é necessário para corresponder,
             * mas é claro que o IE tem bom's programas.
             */
            if (!$this->ieNoOpaque && $this->_calcOpaque() !== $data["opaque"])
            {
                return $this->challengeClient();
            }

            /**
             * Procure o hash da senha da pessoa.
             * Se não for encontrado, negue o acesso. Isso não faz
             * suposições sobre como o hash da senha foi construído
             * além de que ele deve ter sido construído de forma a
             * ser recriável com as configurações atuais deste
             * objeto.
             */
            $ha1 = $this->digestResolver->resolve($data["username"], $data["realm"]);

            /**
             *
             */
            if ($ha1 === false)
            {
                return $this->challengeClient();
            }

            /**
             * Se MD5-sess for usado, o valor a1 será feito do hash de
             * senha da pessoa com o fornecedor e o cliente nonce anexados,
             * separados por dois pontos.
             */
            if ($this->algo === "MD5-sess")
            {
                $ha1 = hash("md5", $ha1 . ":" . $data["nonce"] . ":" . $data["cnonce"]);
            }

            /**
             * Calcule h(a2). O valor desse hash depende da opção qop
             * selecionada pelo cliente e das funções de hash
             * suportadas.
             */
            switch ($data["qop"])
            {
                case 'auth':
                    $a2 = $this->request->getMethod() . ":" . $data["uri"];
                    break;

                case 'auth-int':
                    /**
                     * Deve ser REQUEST_METHOD . ":" . . ":" . hash(entity-body),
                     * mas isso ainda não é suportado, então caia em nossa
                     * especificação.
                     */

                default:
                    throw new Exception\RuntimeException(
                        "O cliente solicitou uma opção qop não suportada"
                    );
            }

            /**
             * O uso de hash() deve facilitar a parametrização
             * do algoritmo de hash.
             */
            $ha2 = hash('md5', $a2);

            /**
             * Calcule a versão do fornecedor do resumo da solicitação.
             * Isso deve corresponder a $data["response"]. Consulte
             * RFC 2617, seção 3.2.2.1.
             */
            $message = $data["nonce"] . ":" .
                $data["nc"] . ":" .
                $data["cnonce"] . ":" .
                $data["qop"] . ":" .
                $ha2;

            $digest  = hash("md5", $ha1 . ":" . $message);

            /**
             * Se nosso resumo corresponder ao do cliente, deixe-o entrar,
             * caso contrário, retorne um código 401 e saia para impedir
             * o acesso ao recurso protegido.
             */
            if (CryptUtils::compareStrings($digest, $data["response"]))
            {
                $identity = [
                    "username" => $data["username"],
                    "realm" => $data["realm"]
                ];

                return new Authentication\Result(Authentication\Result::SUCCESS, $identity);
            }

            return $this->challengeClient();
        }

        /**
         * Calcular Nonce.
         *
         * @return string O valor de uso único.
         * @codingStandardsIgnoreStart.
         */
        protected function _calcNonce()
        {
            /**
             * @codingStandardsIgnoreEnd.
             *
             * Uma consequência sutil desse cálculo de tempo limite é que
             * ele realmente faz a divisão de todo o tempo em seções de
             * tamanho nonceTimeout, de modo que o valor de tempo limite
             * seja o ponto no tempo do próximo "limite" de aproximação de
             * uma seção. Isso permite que o fornecedor gere consistentemente
             * o mesmo tempo limite (e, portanto, o mesmo valor nonce) entre
             * as solicitações, mas apenas enquanto um desses "limites" não
             * for ultrapassado entre as solicitações. Se isso acontecer, o
             * nonce será alterado por conta própria e efetivamente
             * desconectará a pessoa. Isso seria surpreendente se a pessoa
             * tivesse acabado de fazer login.
             */
            $timeout = ceil(time() / $this->nonceTimeout) * $this->nonceTimeout;
            $userAgentHeader = $this->request->getHeaders()->get("User-Agent");

            if ($userAgentHeader)
            {
                $userAgent = $userAgentHeader->getFieldValue();
            } elseif (isset($_SERVER["HTTP_USER_AGENT"]))
            {
                $userAgent = $_SERVER["HTTP_USER_AGENT"];
            } else
            {
                $userAgent = "Laminas_Authenticaion";
            }

            return hash("md5", $timeout . ":" . $userAgent . ":" . self::class);
        }

        /**
         * Calcular opaco.
         *
         * A sequência de grafemas opaca pode ser qualquer coisa; o cliente
         * deve devolvê-lo exatamente como foi enviado. Pode ser útil armazenar
         * dados nesta string em alguns aplicativos. Idealmente, um novo valor
         * para isso seria gerado toda vez que um cabeçalho WWW-Authenticate
         * for enviado (para reduzir a previsibilidade), mas teríamos que ser
         * capazes de criar o mesmo valor exato em pelo menos duas solicitações
         * separadas do mesmo cliente.
         *
         * @return string O valor opaco.
         * @codingStandardsIgnoreStart.
         */
        protected function _calcOpaque()
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            return hash("md5", "Opaque Data:" . self::class);
        }

        /**
         * Analisar o título Digest Authorization.
         *
         * @param  string $header Autorização do cliente: título HTTP.
         * @return array|bool Elementos de dados do título ou falso
         *                    se qualquer parte do título não for
         *                    muito válida.
         *
         * @codingStandardsIgnoreStart.
         */
        protected function _parseDigestAuth($header)
        {
            /**
             * @codingStandardsIgnoreEnd.
             */
            $temp = null;
            $data = [];

            /**
             * Consulte Laminas-1052. Detecte nomes de pessoas não muito
             * válidos em vez de apenas retornar um código 400.
             */
            $ret = preg_match('/username="([^"]+)"/', $header, $temp);

            if (!$ret || empty($temp[1]) || !ctype_print($temp[1]) || strpos($temp[1], ":") !== false)
            {
                $data["username"] = "::invalid::";
            } else
            {
                $data["username"] = $temp[1];
            }

            $temp = null;
            $ret = preg_match('/realm="([^"]+)"/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            if (!ctype_print($temp[1]) || strpos($temp[1], ":") !== false)
            {
                return false;
            } else
            {
                $data["realm"] = $temp[1];
            }

            $temp = null;
            $ret = preg_match('/nonce="([^"]+)"/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            if (!ctype_xdigit($temp[1]))
            {
                return false;
            }

            $data["nonce"] = $temp[1];
            $temp = null;
            $ret = preg_match('/uri="([^"]+)"/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            /**
             * A seção 3.2.2.5 do RFC 2617 diz que o fornecedor de
             * autenticação deve verificar se o campo URI no título de
             * autorização é para o mesmo recurso solicitado na linha
             * de solicitação.
             */
            $rUri = $this->request->getUri();
            $cUri = UriFactory::factory($temp[1]);

            /**
             * Certifique-se de que a parte do caminho de ambos os
             * URIs seja a mesma.
             */
            if ($rUri->getPath() !== $cUri->getPath())
            {
                return false;
            }

            /**
             * A seção 3.2.2.5 parece sugerir que o valor do URI. O campo
             * de autorização deve ser transformado em um URI absoluto se o.
             * O URI de solicitação é absoluto, mas é vago e é um monte de
             * código que não quero escrever agora.
             */
            $data["uri"] = $temp[1];
            $temp = null;
            $ret = preg_match('/response="([^"]+)"/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            if (!$this->isValidMd5Hash($temp[1]))
            {
                return false;
            }

            $data["response"] = $temp[1];
            $temp = null;

            /**
             * A especificação diz que normalmente deve ser MD5 se omitido.
             * OK, então como isso se encaixa com o algo que enviamos no
             * título WWW-Authenticate, se ele pode ser facilmente
             * substituído pelo cliente ?
             */
            $ret = preg_match('/algorithm="?(' . $this->algo . ')"?/', $header, $temp);

            if ($ret && ! empty($temp[1]) && in_array($temp[1], $this->supportedAlgos))
            {
                $data["algorithm"] = $temp[1];
            } else
            {
                /**
                 * = $this->algo; ?
                 */
                $data["algorithm"] = "MD5";
            }

            $temp = null;

            /**
             * Não é opcional nesta implementação.
             */
            $ret = preg_match('/cnonce="([^"]+)"/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            if (!ctype_print($temp[1]))
            {
                return false;
            }

            $data["cnonce"] = $temp[1];
            $temp = null;

            /**
             * Se o fornecedor enviou um valor opaco, o cliente deve
             * devolvê-lo.
             */
            if ($this->useOpaque)
            {
                $ret = preg_match('/opaque="([^"]+)"/', $header, $temp);

                if (!$ret || empty($temp[1]))
                {
                    /**
                     * Grande surpresa: o IE não é compatível com RFC 2617.
                     */
                    $headers = $this->request->getHeaders();

                    if (!$headers->has("User-Agent"))
                    {
                        return false;
                    }

                    $userAgent = $headers->get("User-Agent")->getFieldValue();

                    if (false === strpos($userAgent, "MSIE"))
                    {
                        return false;
                    }

                    $temp[1] = "";
                    $this->ieNoOpaque = true;
                }

                /**
                 * Esta implementação envia apenas strings hexadecimais
                 * MD5 no valor opaco.
                 */
                if (!$this->ieNoOpaque && !$this->isValidMd5Hash($temp[1]))
                {
                    return false;
                }

                $data["opaque"] = $temp[1];
                $temp = null;
            }

            /**
             * Não é opcional nesta implementação, mas deve ser um
             * dos tipos qop suportados.
             */
            $ret = preg_match('/qop="?(' . implode('|', $this->supportedQops) . ')"?/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            if (!in_array($temp[1], $this->supportedQops))
            {
                return false;
            }

            $data["qop"] = $temp[1];
            $temp = null;

            /**
             * Não é opcional nesta implementação. A especificação diz
             * que esse valor não deve ser uma string entre aspas, mas
             * aparentemente algumas implementações o citam de qualquer
             * maneira. Ver Lâminas-1544.
             */
            $ret = preg_match('/nc="?([0-9A-Fa-f]{8})"?/', $header, $temp);

            if (!$ret || empty($temp[1]))
            {
                return false;
            }

            if (8 !== strlen($temp[1]) || ! ctype_xdigit($temp[1]))
            {
                return false;
            }

            $data["nc"] = $temp[1];

            return $data;
        }

        /**
         * valida se $value é um hash Md5 válido.
         *
         * @param string $value.
         * @return bool.
         */
        private function isValidMd5Hash($value)
        {
            return 32 === strlen($value) && ctype_xdigit($value);
        }
    }
