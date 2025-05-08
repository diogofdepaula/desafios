package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"sync"
	"sync/atomic" // <--- Importar pacote atomic
	"time"         // <--- Importar pacote time

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/ripemd160"
)

// Estrutura para guardar o resultado encontrado
type Result struct {
	PrivateKeyHex string
	Address       string
}

// Contador atômico para chaves verificadas
var checkedKeys atomic.Uint64 // <-- Variável global para contar

func main() {
	// --- Definição e Parsing dos Argumentos ---
	maskedKeyHex := flag.String("key", "", "Chave privada hexadecimal mascarada com 'x' (ex: 00...x2cx5)")
	targetAddress := flag.String("addr", "", "Endereço Bitcoin alvo (ex: 1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum)")
	numCores := flag.Int("cores", runtime.NumCPU(), "Número de núcleos de CPU a utilizar (padrão: todos os disponíveis)")
	flag.Parse()

	// --- Validação dos Argumentos ---
	if *maskedKeyHex == "" || *targetAddress == "" {
		fmt.Println("Erro: Os argumentos -key e -addr são obrigatórios.")
		flag.Usage()
		os.Exit(1)
	}
	if len(*maskedKeyHex) != 64 {
		log.Fatalf("Erro: A chave privada hexadecimal deve ter 64 caracteres.")
	}
	if *numCores <= 0 {
		log.Fatalf("Erro: O número de núcleos deve ser positivo.")
	}
	runtime.GOMAXPROCS(*numCores)

	log.Printf("Iniciando busca pela chave privada para o endereço: %s", *targetAddress)
	log.Printf("Usando chave mascarada: %s", *maskedKeyHex)
	log.Printf("Utilizando %d núcleos de CPU.", *numCores)

	// --- Preparação para a Busca ---
	xIndices := findXIndices(*maskedKeyHex)
	numX := len(xIndices)
	if numX == 0 {
		log.Fatalf("Erro: Nenhuma máscara 'x' encontrada na chave fornecida.")
	}

	hexChars := "0123456789abcdef"
	totalCombinations := new(big.Int).Exp(big.NewInt(16), big.NewInt(int64(numX)), nil)
	log.Printf("Número total de combinações a serem testadas: %s (%d máscaras 'x')", totalCombinations.String(), numX)
	if totalCombinations.Cmp(big.NewInt(0)) == 0 {
		log.Fatalf("Erro: Cálculo de combinações resultou em zero.")
	}

	// --- Configuração do Paralelismo ---
	var wg sync.WaitGroup
	resultsChan := make(chan Result, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Goroutine de Status Periódico --- <--- NOVO BLOCO
	go func(ctx context.Context) {
		ticker := time.NewTicker(60 * time.Second) // Dispara a cada 60 segundos
		defer ticker.Stop()

		var lastCount uint64 = 0
		startTime := time.Now()
		lastTimestamp := startTime

		log.Println("Monitor de status iniciado (atualizações a cada 60s).")

		for {
			select {
			case <-ticker.C: // Quando o ticker disparar
				currentCount := checkedKeys.Load() // Lê o valor atual do contador atômico
				currentTimestamp := time.Now()

				// Calcula a taxa desde a última verificação
				keysInInterval := currentCount - lastCount
				elapsedSeconds := currentTimestamp.Sub(lastTimestamp).Seconds()
				var rate float64
				if elapsedSeconds > 0 {
					rate = float64(keysInInterval) / elapsedSeconds
				} else {
					rate = 0 // Evita divisão por zero
				}

				// Calcula a taxa média geral
                totalElapsedSeconds := currentTimestamp.Sub(startTime).Seconds()
                var avgRate float64
                if totalElapsedSeconds > 0 {
                     avgRate = float64(currentCount) / totalElapsedSeconds
                } else {
                     avgRate = 0
                }


				log.Printf("Status: %.2f chaves/s (último min) | Média: %.2f chaves/s | Total: %d",
					rate, avgRate, currentCount)

				// Atualiza para a próxima iteração
				lastCount = currentCount
				lastTimestamp = currentTimestamp

			case <-ctx.Done(): // Quando a busca principal terminar (encontrado ou concluído)
				log.Println("Monitor de status finalizado.")
				return // Sai da goroutine de status
			}
		}
	}(ctx) // Passa o contexto para a goroutine de status poder ser cancelada

	// --- Lançamento das Goroutines (Workers) ---
	numWorkers := *numCores
	combinationsPerWorker := new(big.Int).Div(totalCombinations, big.NewInt(int64(numWorkers)))
	remainder := new(big.Int).Mod(totalCombinations, big.NewInt(int64(numWorkers)))
	log.Printf("Distribuindo o trabalho entre %d workers...", numWorkers)

	startCombination := big.NewInt(0)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)

		endCombination := new(big.Int).Set(startCombination)
		currentChunkSize := new(big.Int).Set(combinationsPerWorker)
		if remainder.Cmp(big.NewInt(0)) > 0 {
			currentChunkSize.Add(currentChunkSize, big.NewInt(1))
			remainder.Sub(remainder, big.NewInt(1))
		}
		endCombination.Add(endCombination, currentChunkSize)

		workerID := i
		workerStart := new(big.Int).Set(startCombination)
		workerEnd := new(big.Int).Set(endCombination)
		maskedKeyCopy := *maskedKeyHex
		targetAddrCopy := *targetAddress

		go func(id int, start, end *big.Int, maskedKey, targetAddr string) {
			defer wg.Done()
			// Removido log de início de worker para não poluir tanto com o status
			// log.Printf("Worker %d iniciado (Range: %s a %s)", id, start.String(), new(big.Int).Sub(end, big.NewInt(1)).String())

			currentCombinationIndex := new(big.Int).Set(start)

			for currentCombinationIndex.Cmp(end) < 0 {
				select {
				case <-ctx.Done():
					// log.Printf("Worker %d cancelado.", id) // Log opcional
					return
				default:
				}

				candidateKeyHex := generateCandidateKey(maskedKey, xIndices, currentCombinationIndex, numX, hexChars)

				// Incrementa o contador ANTES de verificar a chave <--- ALTERAÇÃO AQUI
				checkedKeys.Add(1)

				valid, derivedAddr := checkPrivateKey(candidateKeyHex, targetAddr)
				if valid {
					log.Printf("!!! SUCESSO pelo Worker %d !!!", id)
					select {
					case resultsChan <- Result{PrivateKeyHex: candidateKeyHex, Address: derivedAddr}:
						// log.Printf("Worker %d enviou o resultado.", id) // Log opcional
					case <-ctx.Done():
						// log.Printf("Worker %d encontrou resultado, mas busca já cancelada.", id) // Log opcional
						return
					}
					cancel()
					return
				}

				currentCombinationIndex.Add(currentCombinationIndex, big.NewInt(1))
			}
			// log.Printf("Worker %d completou seu range sem sucesso.", id) // Log opcional
		}(workerID, workerStart, workerEnd, maskedKeyCopy, targetAddrCopy)

		startCombination.Set(workerEnd)
	}

	// --- Esperar Resultados ---
	resultFound := false // Flag para saber se encontramos o resultado

	// Goroutine para fechar o canal de resultados APÓS todos os workers terminarem
	go func() {
		wg.Wait()
		close(resultsChan)
		log.Println("Todos os workers terminaram.")
	}()

	// Ler do canal de resultados
	foundResult, ok := <-resultsChan
	if ok {
		resultFound = true // Marca que encontramos
		fmt.Println("\n========================================")
		fmt.Printf(">>> Chave Privada Encontrada: %s\n", foundResult.PrivateKeyHex)
		fmt.Printf(">>> Endereço Verificado:      %s\n", foundResult.Address)
		fmt.Println("========================================")
	}

	// Espera um pouco para o último status ser impresso se o resultado foi encontrado muito rápido
	// ou se a busca terminou sem sucesso.
	if !resultFound {
		<-ctx.Done() // Se não encontrou, espera o cancelamento (que não ocorrerá) ou um sinal externo
                     // Na prática, a goroutine wg.Wait fechará resultsChan, saindo do range se ok for false
        log.Println("Busca concluída sem sucesso.")
	} else {
        // Se encontrou, o cancel() já foi chamado, o ctx.Done() será sinalizado.
        // A goroutine de status vai parar.
        // A goroutine wg.Wait() ainda precisa terminar para fechar o resultsChan.
    }

    // Imprime uma estatística final
    finalCount := checkedKeys.Load()
    log.Printf("Verificação finalizada. Total de chaves testadas: %d", finalCount)

}

// findXIndices (sem alterações)
func findXIndices(maskedKey string) []int {
	indices := []int{}
	for i, char := range maskedKey {
		if char == 'x' || char == 'X' {
			indices = append(indices, i)
		}
	}
	return indices
}

// generateCandidateKey (sem alterações)
func generateCandidateKey(template string, xIndices []int, combinationIndex *big.Int, numX int, hexChars string) string {
	candidateRunes := []rune(template)

	tempIndex := new(big.Int).Set(combinationIndex)
	divisor := big.NewInt(16)
	remainder := new(big.Int)

	for i := numX - 1; i >= 0; i-- {
		tempIndex.DivMod(tempIndex, divisor, remainder)
		hexCharIndex := remainder.Int64()

		xPos := xIndices[i]
		candidateRunes[xPos] = rune(hexChars[hexCharIndex])

		if tempIndex.Cmp(big.NewInt(0)) == 0 && i > 0 {
			for j := i - 1; j >= 0; j-- {
				candidateRunes[xIndices[j]] = rune(hexChars[0])
			}
			break
		}
	}

	return string(candidateRunes)
}

// checkPrivateKey (sem alterações da última versão)
func checkPrivateKey(privKeyHex string, targetAddress string) (bool, string) {
	privateKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return false, ""
	}
	_, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	if pubKey == nil {
		return false, ""
	}
	compressedPubKeyBytes := pubKey.SerializeCompressed()
	pubKeySha256 := sha256.Sum256(compressedPubKeyBytes)
	ripemd160Hasher := ripemd160.New()
	_, err = ripemd160Hasher.Write(pubKeySha256[:])
	if err != nil {
		log.Printf("Erro interno no RIPEMD160: %v", err)
		return false, ""
	}
	pubKeyHash := ripemd160Hasher.Sum(nil)
	addressPubKeyHash, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		log.Printf("Erro ao criar AddressPubKeyHash: %v", err)
		return false, ""
	}
	derivedAddress := addressPubKeyHash.EncodeAddress()
	return derivedAddress == targetAddress, derivedAddress
}
