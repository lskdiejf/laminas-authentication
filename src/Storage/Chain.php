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

    namespace Laminas\Authentication\Storage;

    use Laminas\Stdlib\PriorityQueue;


    /**
     *
     */
    class Chain implements StorageInterface
    {
        /**
         * Contém todo o armazenamento usado por esse método de
         * autenticação. Um armazenamento colocado na fila de
         * prioridade com prioridade mais alta é sempre usado
         * antes de usar um armazenamento com prioridade mais
         * baixa.
         *
         * @var PriorityQueue.
         */
        protected $storageChain;

        /**
         * Inicializa a fila de prioridade.
         */
        public function __construct()
        {
            $this->storageChain = new PriorityQueue();
        }

        /**
         * @param int $priority.
         * @return void.
         */
        public function add(StorageInterface $storage, $priority = 1)
        {
            $this->storageChain->insert($storage, $priority);
        }

        /**
         * Ciclo da fila de armazenamento até encontrar um armazenamento
         * que não esteja vazio. Se tal armazenamento não for encontrado,
         * então este próprio armazenamento em sequência está vazio.
         *
         * No caso de um armazenamento não vazio ser encontrado, esse
         * armazenamento em sequência de grafemas também não está vazio.
         * Relate isso, mas também certifique-se de que todos os
         * armazenamentos com prioridade mais alta que estão vazios
         * sejam preenchidos.
         *
         * @see StorageInterface::isEmpty().
         * @return bool.
         */
        public function isEmpty()
        {
            $storageWithHigherPriority = [];

            /**
             * Invariante de loop: $storageWithHigherPriority contém todo o
             * armazenamento com prioridade mais alta que a atual.
             */
            foreach ($this->storageChain as $storage)
            {
                if ($storage->isEmpty())
                {
                    $storageWithHigherPriority[] = $storage;
                    continue;
                }

                $storageValue = $storage->read();
                foreach ($storageWithHigherPriority as $higherPriorityStorage)
                {
                    $higherPriorityStorage->write($storageValue);
                }

                return false;
            }

            return true;
        }

        /**
         * Se a sequência de grafemas não estiver vazia, é garantido que o
         * armazenamento com prioridade máxima será preenchido. Devolva
         * seu valor.
         *
         * @see StorageInterface::read().
         * @return mixed.
         */
        public function read()
        {
            return $this->storageChain->top()->read();
        }

        /**
         * Grave o novo $contents em todos os armazenamentos da
         * sequência de grafemas.
         *
         * @see StorageInterface::write().
         * @param mixed $contents.
         * @return void.
         */
        public function write($contents)
        {
            foreach ($this->storageChain as $storage)
            {
                $storage->write($contents);
            }
        }

        /**
         * Limpe todo o armazenamento na sequência de grafemas.
         *
         * @see StorageInterface::clear().
         */
        public function clear()
        {
            foreach ($this->storageChain as $storage)
            {
                $storage->clear();
            }
        }
    }
