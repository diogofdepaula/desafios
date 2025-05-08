package main

import (
	"flag" // Importar pacote flag
	"fmt"
	"log"
	"math/big"
	"os" // Importar pacote os para sair em caso de erro (usado apenas para flag.PrintDefaults e Fatal)
	"runtime" // Importar pacote runtime
	"strings"
	"sync" // Importar pacote sync para WaitGroup
	"sync/atomic" // Importar pacote atomic para operações atômicas
	"time"

	// Importar as bibliotecas externas necessárias
	"github.com/tyler-smith/go-bip39"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/btcutil"
	// "github.com/btcsuite/btcd/btcec" // Geralmente não precisa importar diretamente
)

// Função para calcular potência para big.Int (base^exp)
func bigIntPow(base *big.Int, exp int) *big.Int {
	result := big.NewInt(1)
	b := new(big.Int).Set(base) // Use uma cópia para evitar modificar o base original
	for i := 0; i < exp; i++ {
		result.Mul(result, b)
	}
	return result
}

// Estrutura para passar o resultado encontrado pelos workers
type foundResult struct {
	mnemonic     string
	derivedAddress string
	privateKeyWIF string // Armazenará a chave privada no formato WIF
	// Não precisamos passar a chave estendida aqui, pois ela pode ser obtida
	// na goroutine de impressão a partir do mnemônico encontrado.
}

func main() {
	// Definir as flags de linha de comando
	mnemonicStringFlag := flag.String("teste", "", "Frase mnemônica com 'xxx' nas posições a serem testadas, ex: 'web dress lawn violin theory xxx south sorry gun bunker exact accident'")
	numCoresFlag := flag.Int("cores", runtime.NumCPU(), "Número de núcleos de CPU a serem usados. Padrão é o número de núcleos disponíveis.")

	// Analisar os argumentos da linha de comando
	flag.Parse()

	// Configurar o número de núcleos de CPU a serem usados
	numWorkers := *numCoresFlag
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU() // Usar todos os núcleos se 0 ou negativo for fornecido
	}
	runtime.GOMAXPROCS(numWorkers)
	fmt.Printf("Usando %d núcleos de CPU.\n", numWorkers)


	// Verificar se a flag "teste" foi fornecida
	if *mnemonicStringFlag == "" {
		fmt.Println("Uso: ./findwords -teste=\"palavra1 palavra2 xxx ... palavra12\" [-cores=N]")
		flag.PrintDefaults()
		os.Exit(1) // Sair se o argumento não for fornecido
	}

	// Dividir a string de entrada em palavras
	originalWords := strings.Fields(*mnemonicStringFlag)

	// Verificar se a lista tem 12 palavras
	if len(originalWords) != 12 {
		log.Fatalf("A frase mnemônica deve conter exatamente 12 palavras (incluindo os marcadores 'xxx'). Foi fornecido %d palavras.", len(originalWords))
	}

	//targetAddressStr := "1949jMYwRMkWdaudi62Gg8oarsEDUeaqAV" // Endereço P2PKH alvo original
	targetAddressStr := "1949jMYwRMkWdaudi62Gg8oarsEDUeaqAV" // Endereço P2PKH alvo que você testou

	// Encontrar os índices das palavras marcadas com "xxx"
	var xxxIndices []int
	for i, word := range originalWords {
		if word == "xxx" {
			xxxIndices = append(xxxIndices, i)
		}
	}

	// Verificar se há pelo menos um "xxx"
	if len(xxxIndices) == 0 {
		log.Fatal("Nenhuma palavra marcada com 'xxx' foi encontrada na frase fornecida.")
	}

	numXxx := len(xxxIndices)
	// Obter a lista completa de palavras BIP39 em inglês
	// CORREÇÃO DEFINITIVA para a sua versão da biblioteca:
	// Chama a função GetWordList sem argumentos e atribui o resultado diretamente a bip39WordList.
	// Não espera um erro de retorno.
	bip39WordList := bip39.GetWordList()


	bip39WordListSize := big.NewInt(int64(len(bip39WordList))) // Tamanho da lista BIP39 como big.Int

	// Calcular o número total de tentativas (2048 ^ número de xxx)
	totalAttemptsBig := bigIntPow(bip39WordListSize, numXxx)

	fmt.Println("Iniciando a busca...")
	fmt.Printf("Número de posições a serem testadas: %d\n", numXxx)
	fmt.Printf("Número total de palavras no dicionário BIP39: %s\n", bip39WordListSize.String())
	fmt.Printf("Número total de combinações a serem testadas: %s\n", totalAttemptsBig.String())
	fmt.Printf("Posições 'xxx' (0-based): %v\n", xxxIndices)


	// Canal para enviar as frases mnemônicas para os workers
	mnemonicsChan := make(chan string, numWorkers*2) // Buffer para não bloquear imediatamente
	// Canal para receber o resultado encontrado (apenas um resultado esperado)
	foundChan := make(chan foundResult, 1)
	// WaitGroup para esperar todos os workers E a goroutine de impressão terminarem
	var wg sync.WaitGroup
	// Flag atômica para sinalizar aos workers que a combinação foi encontrada e eles podem parar
	var stopWorkers int32 = 0

	// Definir os parâmetros da rede (Mainnet neste caso)
	chainParams := &chaincfg.MainNetParams

	// Índices de derivação para m/44'/0'/0'/0/0 (Assumindo P2PKH legado)
	pathIndices := []uint32{
		hdkeychain.HardenedKeyStart + 44, // 44'
		hdkeychain.HardenedKeyStart + 0,  // 0' (Bitcoin)
		hdkeychain.HardenedKeyStart + 0,  // 0' (Conta 0)
		0,                                // 0 (Cadeia Externa)
		0,                                // 0 (Primeiro endereço)
	}

	fmt.Printf("Testando com o caminho de derivação: m/44'/0'/0'/0/0\n")

	// Lançar os worker goroutines
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()

			// Worker loop: lê mnemônicos do canal até que ele seja fechado
			for mnemonic := range mnemonicsChan {
				// Verificar se a busca já foi interrompida por outro worker
				if atomic.LoadInt32(&stopWorkers) != 0 {
					return // Sair do worker se a busca foi interrompida
				}

				// Gerar a semente e Derivar Chave/Endereço (lógica movida para o worker)
				seed := bip39.NewSeed(mnemonic, "") // Senha vazia é comum

				masterKey, err := hdkeychain.NewMaster(seed, chainParams)
				if err != nil {
					// log.Printf("Worker %d: Erro ao gerar chave mestra para '%s': %v", workerID, mnemonic, err)
					continue // Pula para o próximo mnemônico
				}

				currentKey := masterKey
				var deriveErr error
				for _, index := range pathIndices {
					currentKey, deriveErr = currentKey.Derive(index)
					if deriveErr != nil {
						// log.Printf("Worker %d: Erro ao derivar caminho para '%s': %v", workerID, mnemonic, deriveErr)
						break // Sai deste loop de derivação
					}
				}

				if deriveErr != nil {
					continue // Pula para o próximo mnemônico se a derivação falhou
				}

				// Obter a chave pública para gerar o endereço
				pubKey, err := currentKey.ECPubKey()
				if err != nil {
					// log.Printf("Worker %d: Erro ao obter chave pública para '%s': %v", workerID, mnemonic, err)
					continue // Pula para o próximo mnemônico
				}

				// Gerar endereço P2PKH
				addressPubKey, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), chainParams)
				if err != nil {
					// log.Printf("Worker %d: Erro ao criar AddressPubKey para '%s': %v", workerID, mnemonic, err)
					continue // Pula para o próximo mnemônico
				}

				derivedAddress := addressPubKey.AddressPubKeyHash().EncodeAddress()

				// Comparar o endereço derivado com o endereço alvo
				if derivedAddress == targetAddressStr {
					// Combinação correta encontrada!
					// Sinalizar aos outros workers para pararem
					atomic.StoreInt32(&stopWorkers, 1)

					// --- Converter a chave privada derivada para o formato WIF ---
					// Obter a chave privada ECDSA de 32 bytes
					privateKeyECDSA, err := currentKey.ECPrivKey()
					if err != nil {
						log.Printf("Worker %d: Erro ao obter chave privada ECDSA para '%s': %v", workerID, mnemonic, err)
						// Continuar a busca, pois este erro não invalida a combinação
						continue
					}

					// Criar um objeto WIF a partir da chave privada ECDSA e da rede
					// Indicamos 'true' para 'compressed' porque as chaves derivadas de HD wallets
					// usam chaves públicas comprimidas, e o WIF deve refletir isso para compatibilidade.
					wif, err := btcutil.NewWIF(privateKeyECDSA, chainParams, true)
					if err != nil {
						log.Printf("Worker %d: Erro ao criar WIF para '%s': %v", workerID, mnemonic, err)
						// Continuar a busca
						continue
					}
					privateKeyWIF := wif.String() // Obtém a string no formato WIF (começa com K ou L na Mainnet)
					// --- Fim da conversão para WIF ---


					// Enviar o resultado para o canal foundChan
					select {
					case foundChan <- foundResult{
						mnemonic:     mnemonic,
						derivedAddress: derivedAddress,
						privateKeyWIF: privateKeyWIF, // Envia a chave privada no formato WIF
					}:
						// Enviado com sucesso
					default:
						// Canal já cheio (outro worker encontrou e enviou primeiro), apenas sair
					}
					return // Sair deste worker goroutine
				}
			}
		}(i) // Passa o ID do worker
	}

	// --- Goroutine para imprimir o resultado encontrado ---
	// Adicionar esta goroutine ao WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done() // Sinaliza ao WaitGroup que esta goroutine terminou

		result := <-foundChan // Espera receber um resultado do canal
		fmt.Printf("\n--- COMBINAÇÃO CORRETA ENCONTRADA! ---\n")
		fmt.Printf("Frase Mnemônica Completa: %s\n", result.mnemonic)
		fmt.Printf("Endereço Gerado: %s\n", result.derivedAddress)

		// --- Imprimir a chave privada estendida e WIF ---
		// Para obter a chave estendida aqui, precisamos derivá-la novamente a partir da semente
		// (que pode ser recriada do mnemônico encontrado).
		seed := bip39.NewSeed(result.mnemonic, "")
		masterKey, err := hdkeychain.NewMaster(seed, chainParams)
		if err != nil {
			log.Printf("Erro ao recriar chave mestra para impressão: %v", err)
			// Continuar a impressão com o que temos
		} else {
			// Derivar a chave estendida para o caminho encontrado
			currentKey := masterKey
			var deriveErr error
			for _, index := range pathIndices {
				currentKey, deriveErr = currentKey.Derive(index)
				if deriveErr != nil {
					log.Printf("Erro ao derivar chave estendida para impressão: %v", deriveErr)
					// Continuar a impressão com o que temos
					break
				}
			}
			if deriveErr == nil {
				// Imprimir a chave privada estendida derivada para o caminho
				fmt.Printf("Chave Privada Derivada (m/44'/0'/0'/0/0) (Estendida - xprv): %s\n", currentKey.String())
			}
		}

		// Imprime a chave WIF que já veio no canal
		fmt.Printf("Chave Privada Derivada (m/44'/0'/0'/0/0) (WIF): %s\n", result.privateKeyWIF)

		// --- Forçar o descarregamento do buffer de saída padrão ---
		// Isso deve garantir que as linhas de impressão sejam escritas.
		os.Stdout.Sync()

		// Não chamamos os.Exit(0) aqui. A goroutine principal e os workers
		// irão terminar naturalmente após a flag stopWorkers ser definida e o canal
		// de mnemônicos ser fechado. Esta goroutine terminará após o Sync().
	}()


	// Variáveis para rastreamento de performance (no goroutine principal)
	attemptsSinceLastReport := 0
	startTime := time.Now()
	reportInterval := 60 * time.Second // Intervalo para o relatório de performance
	attemptCounter := big.NewInt(0) // Contador total de tentativas usando big.Int

	// --- Lógica de Geração de Combinações (no goroutine principal) ---
	currentCombinationIndices := make([]int, numXxx) // Inicializa com zeros [0, 0, ...]

	// Loop principal: Gera combinações e as envia para o canal
	for {
		// Verificar se a busca já foi interrompida por um worker
		if atomic.LoadInt32(&stopWorkers) != 0 {
			break // Sair do loop de geração se a busca foi interrompida
		}

		// 1. Incrementar a combinação de palavras (simulando um contador em base 2048)
		incrementIndex := numXxx - 1
		for incrementIndex >= 0 {
			currentCombinationIndices[incrementIndex]++
			if currentCombinationIndices[incrementIndex] < len(bip39WordList) {
				break // Incremento bem-sucedido
			}
			currentCombinationIndices[incrementIndex] = 0
			incrementIndex--
		}

		// Se incrementIndex < 0, todas as combinações foram testadas
		if incrementIndex < 0 {
			break // Sair do loop de geração
		}

		// 2. Construir a frase mnemônica para a combinação atual
		currentMnemonicWords := make([]string, len(originalWords))
		copy(currentMnemonicWords, originalWords)

		for i, xxxIdx := range xxxIndices {
			wordIndex := currentCombinationIndices[i]
			currentMnemonicWords[xxxIdx] = bip39WordList[wordIndex] // CORREÇÃO: Usar bip39WordList
		}

		mnemonic := strings.Join(currentMnemonicWords, " ")

		// 3. Incrementar o contador total de tentativas (apenas para relatório)
		attemptCounter.Add(attemptCounter, big.NewInt(1))
		attemptsSinceLastReport++ // Contador para o relatório de intervalo

		// 4. Enviar o mnemônico para o canal para ser processado por um worker
		select {
		case mnemonicsChan <- mnemonic:
			// Enviado com sucesso
		case <-time.After(5 * time.Second):
			// Timeout: o canal está cheio e os workers não estão consumindo rápido o suficiente.
			// Isso pode indicar um problema, mas para este caso, apenas logamos e continuamos.
			// Em cenários de busca intensiva, um canal cheio é normal se a geração for mais rápida que o processamento.
			// log.Println("Aviso: Canal de mnemônicos cheio. Workers podem estar lentos.")
		}


		// 5. Verificar se é hora de imprimir o relatório de performance
		now := time.Now()
		elapsed := now.Sub(startTime)

		if elapsed >= reportInterval {
			rate := float64(attemptsSinceLastReport) / elapsed.Seconds()
			// Calcula o progresso total em porcentagem usando big.Float
			progressPercent := new(big.Float).SetInt(attemptCounter)
			progressPercent.Mul(progressPercent, big.NewFloat(100))
			if totalAttemptsBig.Cmp(big.NewInt(0)) > 0 {
				progressPercent.Quo(progressPercent, new(big.Float).SetInt(totalAttemptsBig))
			} else {
				progressPercent.SetFloat64(0.0)
			}
			progressPercentStr := progressPercent.Text('f', 2)


			fmt.Printf("[%s] Relatório de performance (últimos %.2f segundos): %d tentativas processadas. Taxa: %.2f tentativas/segundo. Progresso total: %s / %s (~%s%%).\n",
				now.Format("2006-01-02 15:04:05"),
				elapsed.Seconds(),
				attemptsSinceLastReport,
				rate,
				attemptCounter.String(),
				totalAttemptsBig.String(),
				progressPercentStr,
			)

			// Resetar o contador e o timer
			attemptsSinceLastReport = 0
			startTime = now
		}
	} // Fim do loop de geração

	// Fechar o canal de mnemônicos para sinalizar aos workers que não haverá mais trabalho
	close(mnemonicsChan)

	// Esperar todos os workers E a goroutine de impressão terminarem
	wg.Wait()

	// Se chegarmos aqui e 'stopWorkers' ainda for 0, significa que a combinação não foi encontrada
	if atomic.LoadInt32(&stopWorkers) == 0 {
		// Captura o tempo final para o relatório final
		finalElapsedTime := time.Since(startTime)
		finalAttempts := attemptsSinceLastReport

		if finalAttempts > 0 {
			rate := float64(finalAttempts) / finalElapsedTime.Seconds()
			fmt.Printf("[%s] Relatório final parcial (últimos %.2f segundos): %d tentativas processadas. Taxa: %.2f tentativas/segundo.\n",
				time.Now().Format("2006-01-02 15:04:05"),
				finalElapsedTime.Seconds(),
				finalAttempts,
				rate,
			)
		}
		fmt.Printf("\nNenhuma combinação de palavras para as posições 'xxx' resultou no endereço alvo %s.", targetAddressStr)
		fmt.Println("Verifique a lista de palavras original, o endereço alvo, o caminho de derivação (m/44'/0'/0'/0/0) e se uma senha (passphrase) foi usada.")
		fmt.Println("Considere testar um caminho de derivação diferente (BIP49 para endereços '3...' ou BIP84 para endereços 'bc1...').")
	}

	// O programa sairá naturalmente após o WaitGroup se nada for encontrado.
}
