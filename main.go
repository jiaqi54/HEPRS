package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

var X_ENCRYPT_SIZE int
var COEF_ENCRYPT_SIZE int

func readCsvFile(filePath string) [][]float64 {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatal("Unable to read input file "+filePath, err)
	}
	defer f.Close()

	csvReader := csv.NewReader(f)
	records, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal("Unable to parse file as CSV for "+filePath, err)
	}

	coefs := make([][]float64, len(records))
	for i, a := range records {
		temp := make([]float64, len(a))
		for j, b := range a {
			temp[j], err = strconv.ParseFloat(b, 64)
			if err != nil {
				panic(err)
			}
		}
		coefs[i] = temp
	}

	return coefs
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tHeapSys = %v MiB", bToMb(m.HeapSys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func get_HeapSys() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapSys
}

func read_ciphertext(d1 int, d2 int, filepath string) [][]*ckks.Ciphertext {
	read, _ := os.ReadFile(filepath + "/data_byte")
	d3 := len(read) / d1 / d2
	ciphertext := make([][]*ckks.Ciphertext, d1)
	for i := 0; i < d1; i++ {
		cipher := make([]*ckks.Ciphertext, d2)
		for j := 0; j < d2; j++ {
			var cc ckks.Ciphertext
			cc.UnmarshalBinary(read[(i*d2+j)*d3 : (i*d2+j+1)*d3])
			cipher[j] = &cc
		}
		ciphertext[i] = cipher
	}
	return ciphertext
}

func write_ciphertext(data [][]*ckks.Ciphertext, name string) {

	var empty = []byte{}
	for _, xrow := range data {
		for _, x := range xrow {
			write, _ := x.MarshalBinary()
			empty = append(empty, write...)
		}
	}

	err := os.WriteFile(name+"/data_byte", empty, 0644)
	if err != nil {
		panic(err)
	}

}

func he_inner_product(evaluator ckks.Evaluator, pt []*ckks.Ciphertext, ct []*ckks.Ciphertext, slots int) *ckks.Ciphertext {
	var r *ckks.Ciphertext
	for i := range pt {
		ct_new := evaluator.MulRelinNew(pt[i], ct[i])
		if r == nil {
			r = ct_new
		} else {
			evaluator.Add(ct_new, r, r)
		}
	}

	evaluator.InnerSumLog(r, 1, slots, r)
	return r
}

func encrypt_plain_vector(encryptor ckks.Encryptor, plain_vec []*ckks.Plaintext) []*ckks.Ciphertext {
	cipher_vec := make([]*ckks.Ciphertext, len(plain_vec))
	for i := range plain_vec {
		cipher_vec[i] = encryptor.EncryptNew(plain_vec[i])
	}
	return cipher_vec
}

func encode_float_vector(encoder ckks.Encoder, vec []float64, log_slots int, max_level int, scale float64) []*ckks.Plaintext {
	n := len(vec)
	slots := 1 << log_slots
	n_elem := 1 + ((n - 1) / slots)

	plain_vec := make([]*ckks.Plaintext, n_elem)

	slice := make([]float64, slots)
	for i := range plain_vec {
		start_index := i * slots
		end_index := start_index + slots
		for ind := start_index; ind < end_index; ind++ {
			if ind < n {
				slice[ind-start_index] = float64(vec[ind])
			} else {
				slice[ind-start_index] = 0
			}
		}
		plain_vec[i] = encoder.EncodeNew(slice, max_level, scale, log_slots)
	}

	return plain_vec
}

func decrypt_dot(decryptor ckks.Decryptor, encoder ckks.Encoder, dotVec *ckks.Ciphertext, log_slots int) []complex128 {
	vecDotEncode := decryptor.DecryptNew(dotVec)
	dot := encoder.Decode(vecDotEncode, log_slots)
	return dot
}

func encrypt_mat(encoder ckks.Encoder, encryptor ckks.Encryptor, data [][]float64, log_slots int, max_level int, scale float64) [][]*ckks.Ciphertext {
	matEncrpyt := make([][]*ckks.Ciphertext, len(data))
	for i := range data {

		dataEncode := encode_float_vector(encoder, data[i], log_slots, max_level, scale)
		dataEncrypt := encrypt_plain_vector(encryptor, dataEncode)

		matEncrpyt[i] = dataEncrypt
	}
	return matEncrpyt
}

func run_model(evaluator ckks.Evaluator, coef_data_encrpyt [][]*ckks.Ciphertext, x_data_encrpyt [][]*ckks.Ciphertext, log_slots int) [][]*ckks.Ciphertext {
	slots := 1 << log_slots
	modOutEncrypt := make([][]*ckks.Ciphertext, len(coef_data_encrpyt))
	for i := range coef_data_encrpyt {
		line := make([]*ckks.Ciphertext, len(x_data_encrpyt))
		for j := range x_data_encrpyt {
			dotEncrypt := he_inner_product(evaluator, coef_data_encrpyt[i], x_data_encrpyt[j], slots)
			line[j] = dotEncrypt
		}
		modOutEncrypt[i] = line
	}
	return modOutEncrypt
}

func decrpyt_model_output(encoder ckks.Encoder, decryptor ckks.Decryptor, modelOutput [][]*ckks.Ciphertext, log_slots int, N_SAMPLE int, N_PHENO int) [][]float64 {
	vecDecrypt := make([][]float64, len(modelOutput))
	for i := range modelOutput {
		line := make([]float64, len(modelOutput[0]))
		for j := range modelOutput[0] {
			dotVec := decrypt_dot(decryptor, encoder, modelOutput[i][j], log_slots)
			a := real(dotVec[0])
			//scaling procedure for model 3 and 4
			line[j] = a
		}
		vecDecrypt[i] = line
	}
	//changed matrix dimentions (5 columns)
	vecT := make([][]float64, N_SAMPLE)
	for i := 0; i < N_SAMPLE; i++ {
		temp := make([]float64, N_PHENO)
		for j := 0; j < N_PHENO; j++ {
			temp[j] = vecDecrypt[j][i]
		}
		vecT[i] = temp
	}

	return vecT
}

func Encrypt_model(pk *rlwe.PublicKey, params ckks.Parameters, filepath string, max_level int, dir_name string) {

	coefs := readCsvFile(filepath)

	log_slots := params.LogSlots()
	scale := params.DefaultScale()

	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, pk)
	coef_data_encrypt := encrypt_mat(encoder, encryptor, coefs, log_slots, max_level, scale)

	slots := 1 << log_slots
	COEF_ENCRYPT_SIZE = 1 + ((len(coefs[0]) - 1) / slots)

	err := os.Chdir(dir_name)
	if err != nil {
		panic(err)
	}

	if info, err := os.Stat("coef_data_encrypt"); os.IsNotExist(err) {
		err = os.Mkdir("coef_data_encrypt", 0755)
		if err != nil {
			panic(err)
			fmt.Println(info)
		}
	}

	write_ciphertext(coef_data_encrypt, "coef_data_encrypt")
}

func Encrypt_input(filepath string, params ckks.Parameters, dir_name string, n_sample int64) (*rlwe.RelinearizationKey, *rlwe.RotationKeySet, ckks.Parameters, *rlwe.PublicKey, *rlwe.SecretKey, int, int) {

	x_data := readCsvFile(filepath)[:n_sample]
	N_SAMPLE := len(x_data)

	log_slots := params.LogSlots()
	max_level := 2
	scale := params.DefaultScale()

	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 2)
	rot_keys := kgen.GenRotationKeysForInnerSum(sk)

	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, pk)

	slots := 1 << log_slots
	x_data_encrypt := encrypt_mat(encoder, encryptor, x_data, log_slots, max_level, scale)

	X_ENCRYPT_SIZE = 1 + ((len(x_data[0]) - 1) / slots)

	err := os.Chdir(dir_name)
	if err != nil {
		panic(err)
	}

	if info, err := os.Stat("x_data_encrypt"); os.IsNotExist(err) {
		err = os.Mkdir("x_data_encrypt", 0755)
		if err != nil {
			panic(err)
			fmt.Println(info)
		}
	}
	write_ciphertext(x_data_encrypt, "x_data_encrypt")

	err = os.Chdir("..")
	if err != nil {
		panic(err)
	}

	return rlk, rot_keys, params, pk, sk, max_level, N_SAMPLE
}

func Run_model_encrypt(N_SAMPLE int, N_PHENO int, params ckks.Parameters, rlk *rlwe.RelinearizationKey, rot_keys *rlwe.RotationKeySet, filepath1 string, filepath2 string, filepath3 string) {

	log_slots := params.LogSlots()
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rot_keys})
	x_data_encrypt := read_ciphertext(N_SAMPLE, X_ENCRYPT_SIZE, "x_data_encrypt")
	coef_data_encrpyt := read_ciphertext(N_PHENO, COEF_ENCRYPT_SIZE, "coef_data_encrypt")
	model_output := run_model(evaluator, coef_data_encrpyt, x_data_encrypt, log_slots)

	if info, err := os.Stat(filepath3); os.IsNotExist(err) {
		err = os.Mkdir(filepath3, 0755)
		if err != nil {
			panic(err)
			fmt.Println(info)
		}
	}
	write_ciphertext(model_output, filepath3)
}

func Decrypt_output(N_SAMPLE int, N_PHENO int, params ckks.Parameters, sk *rlwe.SecretKey, pheno_name string, dir_name string) {
	log_slots := params.LogSlots()
	encoder := ckks.NewEncoder(params)
	decryptor := ckks.NewDecryptor(params, sk)
	model_output := read_ciphertext(N_PHENO, N_SAMPLE, "model_output_encrypt")
	pheno_data := decrpyt_model_output(encoder, decryptor, model_output, log_slots, N_SAMPLE, N_PHENO)

	f, err := os.Create("pheno_data_" + pheno_name + ".csv")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err != nil {
		log.Fatalln("failed to open file", err)
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	for _, record := range pheno_data {
		rr := make([]string, len(record))
		for i, f := range record {
			rr[i] = strconv.FormatFloat(f, 'E', -1, 32)
		}
		if err := w.Write(rr); err != nil {
			log.Fatalln("error writing record to file", err)
		}
	}
}
func main() {

	N_PHENO := 1

	// Check command-line arguments
	if len(os.Args) != 7 {
		fmt.Println("Usage: " + os.Args[0] + " </path/to/genotype_data.txt> </path/to/input/model.csv>")
		os.Exit(1)
	}

	var geno_data = os.Args[1]
	var coef_data = os.Args[2]
	var pheno_name = os.Args[3]
	var niter = os.Args[4]
	var param_num = os.Args[5]
	var num_sample = os.Args[6]

	i_param, err := strconv.ParseInt(param_num, 10, 64)
	itnum, err := strconv.ParseInt(niter, 10, 64)
	n_sample, err := strconv.ParseInt(num_sample, 10, 64)
	if err != nil {

	}

	param_string := [5]string{"PN12QP109", "PN13QP218", "PN14QP438", "PN15QP880", "PN16QP1761"}
	param_vec := [5]ckks.ParametersLiteral{ckks.PN12QP109, ckks.PN13QP218, ckks.PN14QP438, ckks.PN15QP880, ckks.PN16QP1761}

	for j := i_param; j < i_param+1; j++ {

		i_param = int64(j)
		// do this for each parameter

		params, err := ckks.NewParametersFromLiteral(param_vec[i_param])
		if err != nil {
			panic(err)
		}

		for i := int64(0); i < itnum; i++ {
			start_it_time := time.Now()
			it_string := strconv.FormatInt(i, 10)
			var dir_name string
			dir_name = param_string[i_param] + "_dir_" + it_string
			times_vec := make([]time.Duration, 5)

			if info, err := os.Stat(dir_name); os.IsNotExist(err) {
				err = os.Mkdir(dir_name, 0755)
				if err != nil {
					panic(err)
					fmt.Println(info)
				}
			}

			// Client encrypts the input, and saves the encrypted data to "x_data_encrypt"
			rlk, rot_keys, params, pk, sk, max_level, N_SAMPLE := Encrypt_input(geno_data, params, dir_name, n_sample)
			fmt.Println("Input Encrypt success")
			// Modeler encrypts model, and saves the encrypted coefficients to "coef_data_encrpyt"
			Encrypt_model(pk, params, coef_data, max_level, dir_name)
			fmt.Println("Model Encrypt success")
			// Evaluator reads "coef_data_encrpyt" and "x_data_encrypt", and saves the output to "model_output_encrypt"
			Run_model_encrypt(N_SAMPLE, N_PHENO, params, rlk, rot_keys, "coef_data_encrpyt", "x_data_encrypt", "model_output_encrypt")
			fmt.Println("Run model success")

			Decrypt_output(N_SAMPLE, N_PHENO, params, sk, pheno_name, dir_name)
			fmt.Println("Decrypt success")
			times_vec[4] = time.Since(start_it_time)
			PrintMemUsage()

			log.Printf("The program "+param_string[i_param]+" took %s", times_vec[4])
			err = os.Chdir("..")
			if err != nil {
				panic(err)
			}
		}

	}
}
