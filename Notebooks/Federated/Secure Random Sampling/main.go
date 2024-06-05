package main

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/mhe"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

type party struct {
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey

	ckgShare    mhe.PublicKeyGenShare
	rkgShareOne mhe.RelinearizationKeyGenShare
	rkgShareTwo mhe.RelinearizationKeyGenShare
	pcksShare   mhe.PublicKeySwitchShare

	input []uint64
}
type multTask struct {
	wg              *sync.WaitGroup
	op1             *rlwe.Ciphertext
	opOut           *rlwe.Ciphertext
	res             *rlwe.Ciphertext
	elapsedmultTask time.Duration
}

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration

func main() {

	l := log.New(os.Stderr, "", 0)

	N := 4 // Number of clients

	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	params, err := heint.NewParametersFromLiteral(heint.ParametersLiteral{
		LogN:             14,
		LogQ:             []int{56, 55, 55, 54, 54, 54},
		LogP:             []int{55, 55},
		PlaintextModulus: 65537,
	})
	if err != nil {
		panic(err)
	}

	crs, err := sampling.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	if err != nil {
		panic(err)
	}

	// Create encoder
	encoder := heint.NewEncoder(params)

	// Target private and public keys
	tsk, tpk := rlwe.NewKeyGenerator(params).GenKeyPairNew()

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, N)

	// Inputs & expected result
	genInputs(params, P)

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P)

	evk := rlwe.NewMemEvaluationKeySet(rlk)

	// Encryption
	encInputs := encPhase(params, P, pk, encoder)

	evaluator := heint.NewEvaluator(params, evk)

	// Create encRes for below summation
	encRes := heint.NewCiphertext(params, 2, params.MaxLevel())

	// Summing up the encrypted values
	runTimed(func() {
		for _, encInput := range encInputs {
			if err := evaluator.Add(encInput, encRes, encRes); err != nil {
				panic(err)
			}
		}
	})

	encOut := pcksPhase(params, tpk, encRes, P)

	decryptor := rlwe.NewDecryptor(params, tsk)
	ptres := heint.NewPlaintext(params, params.MaxLevel())

	// Decryption
	runTimed(func() {
		decryptor.Decrypt(encOut, ptres)
	})

	sum := make([]uint64, params.MaxSlots())
	if err := encoder.Decode(ptres, sum); err != nil {
		panic(err)
	}
	l.Printf("\tTotal number of  depressive: %v\n", sum[0])
	l.Printf("\tTotal number of  non-depressive: %v\n", sum[1])
	l.Printf("\tData partition: %v / %v = %v\n", sum[1], sum[0], sum[1]/sum[0])

}

func encPhase(params heint.Parameters, P []*party, pk *rlwe.PublicKey, encoder *heint.Encoder) []*rlwe.Ciphertext {
	encInputs := make([]*rlwe.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = heint.NewCiphertext(params, 1, params.MaxLevel())
	}

	// Each party encrypts its number
	encryptor := rlwe.NewEncryptor(params, pk)
	for i, pi := range P {
		pt := heint.NewPlaintext(params, params.MaxLevel())
		if err := encoder.Encode(pi.input, pt); err != nil {
			panic(err)
		}
		if err := encryptor.Encrypt(pt, encInputs[i]); err != nil {
			panic(err)
		}
	}

	return encInputs
}

func genparties(params heint.Parameters, N int) []*party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)
	for i := range P {
		pi := &party{}
		pi.sk = rlwe.NewKeyGenerator(params).GenSecretKeyNew()

		P[i] = pi
	}

	return P
}

// Generating inputs for each client
func genInputs(params heint.Parameters, P []*party) {
	l := log.New(os.Stderr, "", 0)
	for i, pi := range P {
		pi.input = make([]uint64, params.N())
		// Assign a floating-point number to each party
		// This can be written by hand, for this 4 client case 3 of them will have 10 depressive 31 non-depressive samples and one of them will have 10 depressive
		if i == 3 {
			pi.input[0] = uint64(10)
			pi.input[1] = uint64(31)
		} else {
			pi.input[0] = uint64(9)
			pi.input[1] = uint64(31)
		}

		l.Printf("Number of depressives for Client %v is: %v\n", i, pi.input[0])
		l.Printf("Number of non-depressives for Client %v is: %v\n\n", i, pi.input[1])
	}
}

func pcksPhase(params heint.Parameters, tpk *rlwe.PublicKey, encRes *rlwe.Ciphertext, P []*party) (encOut *rlwe.Ciphertext) {

	// Collective key switching from the collective secret key to the target public key

	pcks, err := mhe.NewPublicKeySwitchProtocol(params, ring.DiscreteGaussian{Sigma: 1 << 30, Bound: 6 * (1 << 30)})
	if err != nil {
		panic(err)
	}

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShare(params.MaxLevel())
	}

	// Public key switching
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			pcks.GenShare(pi.sk, tpk, encRes, &pi.pcksShare)
		}
	}, len(P))

	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut = heint.NewCiphertext(params, 1, params.MaxLevel())
	elapsedPCKSCloud = runTimed(func() {
		for _, pi := range P {
			if err = pcks.AggregateShares(pi.pcksShare, pcksCombined, &pcksCombined); err != nil {
				panic(err)
			}
		}

		pcks.KeySwitch(encRes, pcksCombined, encOut)
	})

	return
}

func rkgphase(params heint.Parameters, crs sampling.PRNG, P []*party) *rlwe.RelinearizationKey {

	rkg := mhe.NewRelinearizationKeyGenProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	crp := rkg.SampleCRP(crs)

	elapsedRKGParty = runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, &pi.rkgShareOne)
		}
	}, len(P))

	elapsedRKGCloud = runTimed(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.AggregateShares(pi.rkgShareOne, rkgCombined1, &rkgCombined1)
		}
	})

	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, &pi.rkgShareTwo)
		}
	}, len(P))

	rlk := rlwe.NewRelinearizationKey(params)
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			rkg.AggregateShares(pi.rkgShareTwo, rkgCombined2, &rkgCombined2)
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	return rlk
}

func ckgphase(params heint.Parameters, crs sampling.PRNG, P []*party) *rlwe.PublicKey {

	ckg := mhe.NewPublicKeyGenProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	crp := ckg.SampleCRP(crs)

	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			/* #nosec G601 -- Implicit memory aliasing in for loop acknowledged */
			ckg.GenShare(pi.sk, crp, &pi.ckgShare)
		}
	}, len(P))

	pk := rlwe.NewPublicKey(params)

	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShares(pi.ckgShare, ckgCombined, &ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	return pk
}
