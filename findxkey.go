package main

import (
	// "bytes" // Removido - nao usado
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	// "math" // Removido - nao usado
	"math/big"
	"os"
	"os/signal"
	// "runtime" // Removido - nao usado
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

const (
	MASK                 = "6123ax95418x22x11b4a116b4c0c3x514xcf6cfxxx99370cabxbf4f282b4228f"
	TARGET_ADDRESS       = "1EAZegifEThgWjWXuJR9eZZ4TfoXpnenQC"
	PRIVATE_KEY_LEN_HEX  = 64 // Chave privada tem 32 bytes = 64 digitos hex
	BASE58_ALPHABET      = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" // Padrao Bitcoin - Note: Base58 encoder library ja tem o alfabeto, essa constante pode ser redundante dependendo da lib
	LOCAL_COUNT_THRESHOLD = 100000 // Atualiza o contador global a cada 100000 chaves locais
)

var (
	// Contadores e flags compartilhados atomicamente
	keyCount   uint64 // Usamos uint64 para compatibilidade com atomic
	foundFlag  uint32 // Usamos uint32 para compatibilidade com atomic (0 = false, 1 = true)
)

// Helper para preencher uma string com zeros a esquerda
func padLeftWithZeros(str string, desiredLen int) string {
	if len(str) >= desiredLen {
		return str
	}
	paddingLen := desiredLen - len(str)
	return strings.Repeat("0", paddingLen) + str
}

// Aplica a mascara a string de valores 'x'
func applyMask(mask, xValuesHex string) string {
	var fullPrivateKeyHex strings.Builder
	xIndex := 0
	for _, char := range mask {
		if char == 'x' {
			if xIndex < len(xValuesHex) {
				fullPrivateKeyHex.WriteByte(xValuesHex[xIndex])
				xIndex++
			} else {
				// Isso nao deveria acontecer se padLeftWithZeros for usado corretamente
				fullPrivateKeyHex.WriteByte('0')
			}
		} else {
			fullPrivateKeyHex.WriteRune(char)
		}
	}
	return fullPrivateKeyHex.String()
}

// Deriva o endereco publico comprimido a partir da chave privada em bytes
// Retorna o endereco Base58Check e um erro
func derivePublicAddress(privateKeyBytes []byte) (string, error) {
	// 1. Derivar a chave publica a partir da privada
	// Usamos btcec.S256() para a curva secp256k1 otimizada
	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	pubKey := privKey.PubKey()

	// Serializar a chave publica comprimida
	// btcec.NewPublicKey retorna a chave publica comprimida por padrao em v2
	pubKeyCompressed := pubKey.SerializeCompressed() // Deve ter 33 bytes

	// 2. SHA256 do ponto publico comprimido
	sha256Hash := sha256.Sum256(pubKeyCompressed)

	// 3. RIPEMD160 do hash SHA256
	ripemd160Hasher := ripemd160.New()
	_, err := ripemd160Hasher.Write(sha256Hash[:]) // Write espera um slice
	if err != nil {
		return "", fmt.Errorf("ripemd160 write error: %w", err)
	}
	pubKeyHash := ripemd160Hasher.Sum(nil) // Deve ter 20 bytes

	// 4. Preparar dados para Base58Check: Byte de versao (0x00) + hash RIPEMD160
	addressData := append([]byte{0x00}, pubKeyHash...) // Adiciona o prefixo de versao (1 byte)

	// 5. Codificar em Base58Check
	// btcd/btcutil/base58.CheckEncode ja faz o checksum SHA256 duplo
	address := base58.CheckEncode(addressData, 0x00) // O segundo parametro e o byte de versao

	return address, nil
}

// Funcao que cada goroutine executara
func searchKeys(startKey *big.Int, step int, countX int, mask, targetAddress string) {
	currentKey := new(big.Int).Set(startKey) // Copia o valor inicial
	stepBig := big.NewInt(int64(step))

	xHexLen := countX
	var privateKeyBytes [PRIVATE_KEY_LEN_HEX / 2]byte // Buffer para chave privada em bytes
	var derivedAddress string
	// REMOVIDO: var err error // Variavel 'err' na derivacao do endereco eh tratada inline ou no retorno

	localKeyCount := uint64(0) // Contador local

	log.Printf("Goroutine iniciada com chave inicial base-10: %s\n", currentKey.String())

	// Loop de busca infinito
	for {
		// *** VERIFICA O FLAG DE ENCONTRADO AQUI ***
		if atomic.LoadUint32(&foundFlag) == 1 {
			// Antes de sair, soma o contador local restante ao global
			if localKeyCount > 0 {
				atomic.AddUint64(&keyCount, localKeyCount)
			}
			break // Sai do loop
		}

		// 1. Converter o contador (valor 'x') para string hexadecimal
		xValuesHexRaw := currentKey.Text(16)

		// 2. Preencher com zeros a esquerda
		xValuesHexPadded := padLeftWithZeros(xValuesHexRaw, xHexLen)
		if len(xValuesHexPadded) != xHexLen {
            // Isso indica um problema na logica ou que ultrapassamos o espaco de busca
            // log.Printf("Goroutine warning: Padding result length %d != expected %d for key %s", len(xValuesHexPadded), xHexLen, currentKey.String())
            // Neste ponto, se a logica de step/startKey estiver correta E o limite de 16^countX
            // Nao for verificado, currentKey pode crescer indefinidamente, embora o espaco
            // de chaves geradas se repita apos 16^countX.
            // Para um programa de busca real, uma condicao de parada baseada no limite de 16^countX
            // seria essencial aqui. Assumindo por agora que a combinacao startKey/step/loop
            // cobre o espaco corretamente e que a chave alvo esta dentro dele.
            // Vamos apenas pular esta iteracao se o padding falhar de forma inesperada.
             log.Printf("Goroutine %p: padding issue len %d, expected %d for %s", &localKeyCount, len(xValuesHexPadded), xHexLen, xValuesHexRaw)
             // Pula esta iteracao e incrementa a chave para tentar a proxima no step
             currentKey.Add(currentKey, stepBig)
             atomic.AddUint64(&keyCount, 1) // Conta como chave testada (com issue)
             continue

		}


		// 3. Aplicar a mascara
		fullPrivateKeyHex := applyMask(MASK, xValuesHexPadded)

		// Verificar tamanho da chave gerada (deve ser 64 hex)
		if len(fullPrivateKeyHex) == PRIVATE_KEY_LEN_HEX {
			// 4. Converter chave privada hex para bytes
			n, err := hex.Decode(privateKeyBytes[:], []byte(fullPrivateKeyHex))
			if err != nil || n != PRIVATE_KEY_LEN_HEX/2 {
				// log.Printf("Goroutine error: Falha ao decodificar chave hex %s: %v", fullPrivateKeyHex, err) // Opcional, pode gerar muito output
				// Incrementa o contador local e continua
				localKeyCount++
				currentKey.Add(currentKey, stepBig)
				continue // Pula o restante da iteracao
			}

			// 5. Derivar endereco publico
			derivedAddress, err = derivePublicAddress(privateKeyBytes[:])
			if err != nil {
				// log.Printf("Goroutine error: Falha ao derivar endereco para %s: %v", fullPrivateKeyHex, err) // Opcional, pode gerar muito output
				// Incrementa o contador local e continua
				localKeyCount++
				currentKey.Add(currentKey, stepBig)
				continue // Pula o restante da iteracao
			}

			// 6. Comparar com o endereco alvo
			if derivedAddress == targetAddress {
				log.Printf("\nGoroutine ACHOU!!!!!")
				log.Printf("Chave privada encontrada (hex): %s", fullPrivateKeyHex)
				log.Printf("Endereco derivado: %s", derivedAddress)

				// Antes de setar a flag, soma o contador local restante
				if localKeyCount > 0 {
					atomic.AddUint64(&keyCount, localKeyCount)
				}

				// *** SETA O FLAG DE ENCONTRADO AQUI ***
				atomic.StoreUint32(&foundFlag, 1)

				break // Sai do loop
			}
		}
        // else { log.Printf("Goroutine warning: Chave gerada com tamanho incorreto (%d): %s", len(fullPrivateKeyHex), fullPrivateKeyHex); } // Opcional, pode gerar muito output


		// *** INCREMENTAR O CONTADOR LOCAL ***
		localKeyCount++

		// *** PERIODICAMENTE ATUALIZAR O CONTADOR GLOBAL ***
		if localKeyCount >= LOCAL_COUNT_THRESHOLD {
			atomic.AddUint64(&keyCount, localKeyCount)
			localKeyCount = 0 // Reseta o contador local apos adicionar
		}

		// 7. Incrementar o contador da chave pelo tamanho do passo
		currentKey.Add(currentKey, stepBig)

		// TODO: Adicionar uma condicao de parada baseada no tamanho do espaco de busca total para 'x's
		// Se currentKey ultrapassar o limite 16^countX, esta goroutine terminou sua parte do espaco.
		// Calcular o limite maximo (16^countX) com big.Int e comparar currentKey.Cmp(limit) > 0.
		// Se currentKey for maior que o limite, break.
		// Isso exige calcular 16^countX uma vez por goroutine ou passar o limite.
	}

	// Ao sair do loop (seja por achar ou flag), garantir que qualquer contagem local restante seja adicionada
	if localKeyCount > 0 {
		atomic.AddUint64(&keyCount, localKeyCount)
	}

	// log.Printf("Goroutine %p terminou.", &localKeyCount) // Opcional: Para ver qual goroutine terminou
}

// Goroutine para monitorar e imprimir a taxa
func monitor(numWorkers int) {
	// REMOVIDO: startTime := time.Now() // Nao usado, a taxa do intervalo usa intervalStartTime
	// REMOVIDO: lastCount := uint64(0) // Nao usado
	// REMOVIDO: elapsedTime := float64(0) // Nao usado


	fmt.Printf("Iniciando busca com %d goroutines (nucleos)...\n", numWorkers)
	fmt.Printf("Mascara: %s\n", MASK)
	fmt.Printf("Endereco Alvo: %s\n", TARGET_ADDRESS)

	countX := strings.Count(MASK, "x")
	fmt.Printf("Caracteres 'x' na mascara: %d\n", countX)
	// Calcular e imprimir o espaco de busca dos 'x's
	limit := new(big.Int).Exp(big.NewInt(16), big.NewInt(int64(countX)), nil)
	fmt.Printf("Espaco de busca para 'x's (aprox): 16^%d = %s combinacoes\n", countX, limit.String())

	fmt.Printf("Limite de atualizacao atomica local: %d chaves\n", LOCAL_COUNT_THRESHOLD)
	fmt.Printf("\n--- Monitoramento da Taxa de Processamento (Atualiza a cada 30 segundos) ---\n")


	// Timer para imprimir a cada 30 segundos
	ticker := time.NewTicker(30 * time.Second)
	// Nao esquecer de parar o ticker quando a goroutine monitor terminar
    defer ticker.Stop()

	// O timer para calcular a taxa por intervalo de 30s
    intervalStartTime := time.Now()

	for range ticker.C {
		// Verifica se a flag de encontrado foi setada
		if atomic.LoadUint32(&foundFlag) == 1 {
			break // Sai do loop de monitoramento
		}

		// Ler o valor acumulado no contador global e zera-lo para o proximo intervalo.
		// O valor retornado por Swap eh o total acumulado *desde a ultima vez que foi zerado*.
		keysProcessedThisInterval := atomic.SwapUint64(&keyCount, 0)


		elapsedSecondsThisInterval := time.Since(intervalStartTime).Seconds()
        intervalStartTime = time.Now() // Reinicia o timer do intervalo


		if elapsedSecondsThisInterval > 0 {
			rate := float64(keysProcessedThisInterval) / elapsedSecondsThisInterval
			fmt.Printf("Total de chaves testadas nos ultimos %.0f segundos: %d (%.2f chaves/segundo)\n",
				elapsedSecondsThisInterval, keysProcessedThisInterval, rate)
		} else {
             // Caso improvavel de elapsedSecondsThisInterval ser 0
             // Ocorre se o sistema estiver muito sobrecarregado ou o intervalo do ticker for curto demais
             fmt.Printf("Total de chaves testadas nos ultimos %.0f segundos: %d (Calculando taxa...)\n",
                30.0, keysProcessedThisInterval) // Usa 30.0 para a mensagem se elapsed for 0
        }
	}
	log.Println("Monitoramento finalizado.")
}


func main() {
	// Usar log.SetFlags para incluir data/hora nas mensagens de log
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)


	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Uso: %s <numero_de_goroutines>\n", os.Args[0])
		os.Exit(1)
	}

	numWorkers, err := strconv.Atoi(os.Args[1])
	if err != nil || numWorkers <= 0 {
		fmt.Fprintf(os.Stderr, "Numero de goroutines invalido: %v\n", err)
		os.Exit(1)
	}

	// Go utiliza GOMAXPROCS para limitar o numero de threads de OS que executam goroutines.
	// Por padrao, ele usa o numero de nucleos logicos. Definir explicitamente pode ser util
	// para testar como se fosse em um sistema com menos nucleos, mas para performance maxima,
	// deixar o padrao (todos os nucleos) ou definir igual ao numero de goroutines lancadas
	// faz sentido, embora o runtime seja inteligente para gerenciar mais goroutines do que nucleos.
	// runtime.GOMAXPROCS(numWorkers) // Opcional

	// Configurar o tratamento de sinais (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Canal para esperar que todas as goroutines de busca terminem
	// Usamos um WaitGroup em Go para esperar por um grupo de goroutines
    // Isso eh mais idiomatico do que um canal com contagem para este proposito.
    // var wg sync.WaitGroup // Nao podemos usar sync.WaitGroup aqui diretamente
    // pois o main espera no 'select'. O select espera ou pelo sinal OU por um canal
    // que sinaliza que *todos* terminaram. A logica atual com o canal workerDone
    // dentro de uma goroutine separada esperando pelo WaitGroup ou pelo canal
    // e entao fechando 'done' eh uma forma de integrar isso ao select.
    // Mantendo a logica original com o canal workerDone.

	// Determinar o numero de caracteres 'x'
	countX := strings.Count(MASK, "x")
	if countX == 0 {
		log.Fatal("Mascara nao contem 'x'. Nao ha nada para buscar.")
	}
	if len(MASK) != PRIVATE_KEY_LEN_HEX {
		log.Fatalf("Erro: O tamanho da mascara (%d) nao corresponde ao tamanho esperado da chave privada (%d).", len(MASK), PRIVATE_KEY_LEN_HEX)
	}

	// A chave inicial para a contagem dos 'x's comeca em 0
	globalStartKeyForX := big.NewInt(0)

	// Criar goroutines (workers)
	log.Printf("Criando %d goroutines...", numWorkers)

    // Canal para sinalizar que um worker terminou sua parte do trabalho
	workerDone := make(chan struct{}, numWorkers)

	for i := 0; i < numWorkers; i++ {
		// Calcular a chave inicial especifica para esta goroutine
		// A chave inicial para a i-esima goroutine sera globalStartKeyForX + i
		processStartKey := new(big.Int).Add(globalStartKeyForX, big.NewInt(int64(i)))

		// Lanca a goroutine
		go func() {
			searchKeys(processStartKey, numWorkers, countX, MASK, TARGET_ADDRESS)
            // Sinaliza que esta goroutine terminou sua execucao (por encontrar, flag ou esgotar espaco)
			workerDone <- struct{}{}
		}()
	}
    log.Println("Goroutines de busca lancadas.")

	// Lanca a goroutine de monitoramento
	go monitor(numWorkers)

	// Espera por sinal ou por todas as goroutines terminarem
	select {
	case sig := <-sigChan:
		log.Printf("Sinal %s recebido. Sinalizando goroutines para sair...", sig)
		// Seta a flag para sinalizar aos workers e monitor que devem terminar
		atomic.StoreUint32(&foundFlag, 1)

		// Aguarda um curto periodo para dar tempo as goroutines de verem a flag e sair
        // Nao podemos usar o canal workerDone diretamente apos o sinal, pois poderiamos
        // bloquear se uma goroutine ainda nao tivesse terminado.
        // Em uma aplicacao real, usariamos um context.Context.
        log.Println("Aguardando goroutines terminarem graciosamente...")
        time.Sleep(2 * time.Second) // Tempo para goroutines finalizarem apos ver a flag
        log.Println("Tempo de espera apos sinal esgotado.")


	case <-func() chan struct{} { // Goroutine anonima para esperar todos os workers
		done := make(chan struct{})
		go func() {
			for i := 0; i < numWorkers; i++ {
				<-workerDone // Espera cada worker terminar
			}
            // Se chegarmos aqui, todos os workers terminaram
            // Fechamos o canal 'done' para sinalizar o 'select' em main
			close(done)
		}()
		return done
	}():
		log.Println("Todas as goroutines de busca terminaram.")
		// Se chegou aqui porque o canal 'done' foi fechado, significa que todos
		// os workers terminaram por conta propria (encontraram a chave ou esgotaram o espaco).

		// Garantir que o monitor saia apos os workers terminarem
        // Se acharam a chave, a flag foundFlag ja estara 1 e o monitor vai parar no proximo tick.
        // Se terminaram por esgotar o espaco (se implementado), a flag estaria 0.
        // Nesse caso, setamos a flag para que o monitor tambem pare no proximo tick.
         atomic.StoreUint32(&foundFlag, 1) // Sinaliza o monitor para parar
         // Aguarda um curto periodo para garantir que o monitor tenha a chance de ver a flag e parar
         time.Sleep(100 * time.Millisecond)

	}

	log.Println("Programa encerrado.")
}
