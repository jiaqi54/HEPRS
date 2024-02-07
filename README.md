# HEPRS

Here we introduce an application of Fully Homomorphic Encryption (FHE) for secure and private computation of Polygenic Risk Scores (PRS) in genomic studies. Illustrated with the schizophrenia risk prediction, our work employs FHE to perform computations on encrypted genotype data, preserving the privacy and security of sensitive genetic information. Utilizing the CKKs protocol within the Lattigo library, this approach maintains the confidentiality of both genomic data and PRS models within a three-party system involving clients, modelers, and evaluators. 

![text](fig1.png)

The client can be an individual or healthcare provider who possesses private genomic data and seeks obtain PRS calculated based on the genome. The modeler can represent a research institue or a centralized data repository, who builds PRS models off population datasets, which are also sensitive. The evaluator provides the computation power to handle the PRS calculation over large datasets or models. Both the client and modeler don't trust the evaluator to handle the genomic data or model directly, which is where our FHE method comes in. The client would generate a pair a keys, the puclic and secret keys, for encryption and decryption respectively, and only the public key will be shared by the modeler and evaluator. The client and modeler will each encrypt their data using the public key, and send encrypted data to the evaluator. The evaluator will perform calculation directly on encrypted data, without need or capability to decrypt the genomes or the model. The results will be returned to the client in the encrypted form, which can only be decrypted by the client with the secret key. The modeler does need to trust the evaluator not to share the model with the client though. Eventually, only the client will be able to access the plaintext PRS results.

**Encryption Method**

Encryption of the model and inputs is performed using Lattigo, a Go module that implements Ring-Learning-With-Errors-based homomorphic-encryption primitives and Multiparty-Homomorphic-Encryption-based secure protocols. For our task, we use the Full-RNS Homomorphic Encryption for Arithmetic for Approximate Numbers (HEAAN, a.k.a. CKKS) scheme. For more information about the package, please consult https://github.com/tuneinsight/lattigo/tree/master.

**Security level**

With this method 128-bit security is maintained. We implement our method with the following parameter PN13QP218 choice. This includes a ring dimension of 8,192 and logQP equal to 218.

## Usage

To showcase the applicability of our method, the `main.go` contains all 4 steps of the process: input encryption, model encryption, encrypted calculation, and output decryption. To run the program, use command

`go run main.go <genotypes.csv> <betas.csv> <yourphenotype> <NumberIterations> <Moduli> <NumberIndividual>`

`<genotypes.csv>`: Replace with your genotype input. It's in the csv format with each row representing an individual and each column representing an SNP.

`<betas.csv>`: Replace with your model parameters. The number of parameters should be consistent with the number of SNPs in `genotypes.csv`.

`<yourphenotype>`: Name of your phenotype.

`<NumberIterations>`: You can run the program for multiple iterations to evaluate the stochasticity. Use 1 for most cases.

`<Moduli>`: A crucial encryption parameter that balances accuracy and computational cost. We provide built in moduli from 


