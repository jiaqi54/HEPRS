# HEPRS

We introduces a novel application of Fully Homomorphic Encryption (FHE) for secure and private computation of Polygenic Risk Scores (PRS) in genomic studies. Utilizing the CKKs protocol within the Lattigo library, this approach maintains the confidentiality of both genomic data and PRS models within a three-party system involving clients, modelers, and evaluators. 

![](fig1.jpg)

**Encryption Method**

Encryption of the model and inputs is performed using Lattigo, a Go module that implements Ring-Learning-With-Errors-based homomorphic-encryption primitives and Multiparty-Homomorphic-Encryption-based secure protocols. For our task, we use the Full-RNS Homomorphic Encryption for Arithmetic for Approximate Numbers (HEAAN, a.k.a. CKKS) scheme. For more information about the package, please consult https://github.com/tuneinsight/lattigo/tree/master.

**Security level**

With this method 128-bit security is maintained. We implement our method with the following parameter PN13QP218 choice. This includes a ring dimension of 8,192 and logQP equal to 218.

## Usage

Our work is inspired by the 

