package skyscraper

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/rangecheck"
)

func wordsBeHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if field.Cmp(ecc.BN254.ScalarField()) != 0 {
		return fmt.Errorf("bytesHint: expected BN254 Fr, got %s", field)
	}
	if len(inputs) != 2 {
		return fmt.Errorf("bytesHint: expected 2 inputs, got %d", len(inputs))
	}
	wordLen := int(inputs[0].Int64())
	if len(outputs) != 32/wordLen {
		return fmt.Errorf("bytesHint: expected %d outputs, got %d", 32/wordLen, len(outputs))
	}
	bytes := make([]byte, 32)
	inputs[1].FillBytes(bytes)
	for i, o := range outputs {
		o.SetUint64(0)
		for j := range wordLen {
			o.Mul(o, big.NewInt(256))
			o.Add(o, big.NewInt(int64(bytes[wordLen*i+j])))
		}
	}
	return nil
}

// outputs 1 if inputs[0] > inputs[1]
func gtHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return fmt.Errorf("ltHint: expected 2 inputs, got %d", len(inputs))
	}
	if len(outputs) != 1 {
		return fmt.Errorf("ltHint: expected 1 output, got %d", len(outputs))
	}
	if inputs[0].Cmp(inputs[1]) == 1 {
		outputs[0].SetUint64(1)
	} else {
		outputs[0].SetUint64(0)
	}
	return nil
}

func init() {
	solver.RegisterHint(wordsBeHint)
	solver.RegisterHint(gtHint)
}

type Skyscraper struct {
	rc       [8]big.Int
	rc_pow   [18]big.Int // for PoW
	sigma    big.Int
	sboxT    *logderivlookup.Table
	rchk     frontend.Rangechecker
	wordSize int
	api      frontend.API
}

func sboxByte(b byte) byte {
	x := bits.RotateLeft8(^b, 1)
	y := bits.RotateLeft8(b, 2)
	z := bits.RotateLeft8(b, 3)
	return bits.RotateLeft8(b^(x&y&z), 1)
}

func initSbox(api frontend.API, wordSize int) *logderivlookup.Table {
	t := logderivlookup.New(api)
	tableSize := 1 << (8 * wordSize)
	for i := range tableSize {
		r := uint64(0)
		for j := range wordSize {
			shiftSize := j * 8
			inpByte := byte((i >> shiftSize) & 0xff)
			r |= uint64(sboxByte(inpByte)) << shiftSize
		}
		t.Insert(r)
	}
	return t
}

func NewSkyscraper(api frontend.API, wordSize int) *Skyscraper {
	rc := [8]big.Int{}
	rc[0].SetString("17829420340877239108687448009732280677191990375576158938221412342251481978692", 10)
	rc[1].SetString("5852100059362614845584985098022261541909346143980691326489891671321030921585", 10)
	rc[2].SetString("17048088173265532689680903955395019356591870902241717143279822196003888806966", 10)
	rc[3].SetString("71577923540621522166602308362662170286605786204339342029375621502658138039", 10)
	rc[4].SetString("1630526119629192105940988602003704216811347521589219909349181656165466494167", 10)
	rc[5].SetString("7807402158218786806372091124904574238561123446618083586948014838053032654983", 10)
	rc[6].SetString("13329560971460034925899588938593812685746818331549554971040309989641523590611", 10)
	rc[7].SetString("16971509144034029782226530622087626979814683266929655790026304723118124142299", 10)

	sigma := big.Int{}
	sigma.SetString("9915499612839321149637521777990102151350674507940716049588462388200839649614", 10)

	rc_pow := [18]big.Int{}
	rc_pow[0].SetString("0x0000000000000000000000000000000000000000000000000000000000000000", 0)
	rc_pow[1].SetString("0x276b1823ea6d7667081dd27906c83855873125f708a7d269903c4324270bd744", 0)
	rc_pow[2].SetString("0x0cf02bd758a484a6751417914c1a5a18e29d79f3d99e2cb77ac8edbb4b378d71", 0)
	rc_pow[3].SetString("0x25b0e03f18ede5440eb7730d63481db01c3f8e297cca387dfa7adc6769e5bc36", 0)
	rc_pow[4].SetString("0x002882fcbe14ae70955a32e849af80bc33440b966887340457847e652f03cfb7", 0)
	rc_pow[5].SetString("0x039ad8571e2b7a9c12ef02b47f1277ba29989c3e1b37d3c1979231396257d4d7", 0)
	rc_pow[6].SetString("0x1142d5410fc1fc1a4cd48043712f7b29a72a6bc5e6ba2d2bb5b48465abbb7887", 0)
	rc_pow[7].SetString("0x1d78439f69bc0bec44f2c93598f289f717cb3594047999b27ab2c156059075d3", 0)
	rc_pow[8].SetString("0x258588a508f4ff828ddfb8a1ac6f162836ef35a3d55c48b105d7a965138b8edb", 0)
	rc_pow[9].SetString("0x13087879d2f514fe9bc43f6984e4c1579a7367d69a09a95b1596fb9afccb49e9", 0)
	rc_pow[10].SetString("0x17dadee898c452322e9e1eea4bc88a8ee1d72f89ed868012295ccd233b4109fa", 0)
	rc_pow[11].SetString("0x295c6d1546e7f4a6b8e90b1034d5de31b75834b430e9130e9a8590b4aa1f486f", 0)
	rc_pow[12].SetString("0x1288ca0e1d3ed4464ef96a2ba1720f2d07699ef305b92fc3850adcb74c6eb892", 0)
	rc_pow[13].SetString("0x17563b4d1ae023f3e5c81e8991c986628ccad30769371c6901960f9349d1b5ee", 0)
	rc_pow[14].SetString("0x2869043be91a1eea86815a945815f030a1cb0a3add977bc96ba01e9476b32917", 0)
	rc_pow[15].SetString("0x14941f0aff59e79a5d090056095d96cf7475d34f47f414e781776c885511d976", 0)
	rc_pow[16].SetString("0x1ce337a190f4379f318356758a39005abb7142c3cce4fd48bc40b4fd8fc8c034", 0)
	rc_pow[17].SetString("0x0000000000000000000000000000000000000000000000000000000000000000", 0)

	return &Skyscraper{
		rc,
		rc_pow,
		sigma,
		initSbox(api, wordSize),
		rangecheck.New(api),
		wordSize,
		api,
	}
}

func (s *Skyscraper) sbox(v frontend.Variable) frontend.Variable {
	return s.sboxT.Lookup(v)[0]
}

func (s *Skyscraper) square(v frontend.Variable) frontend.Variable {
	return s.api.Mul(s.api.Mul(v, v), s.sigma)
}

func (s *Skyscraper) varFromWordsBe(words []frontend.Variable) frontend.Variable {
	result := frontend.Variable(0)
	for _, b := range words {
		result = s.api.Mul(result, 1<<(8*s.wordSize))
		result = s.api.Add(result, b)
	}
	return result
}

// This works by simulating the long subtraction of ((modulusHi, modulusLo) - 1) - (hi, lo)
// and assert the result is greater than or equal to 0.
// To do that, we produce the carry bit out of thin air and then assert that both digits of the result
// are non-negative (which is to say they are less than 2^128).
func (s *Skyscraper) assertLessThanModulus(hi, lo frontend.Variable) {
	var modulusHi, modulusLoMinusOne, pow128 big.Int
	modulusHi.SetString("30644e72e131a029b85045b68181585d", 16)
	modulusLoMinusOne.SetString("2833e84879b9709143e1f593f0000000", 16)
	pow128.SetInt64(1).Lsh(&pow128, 128)
	borrowS, _ := s.api.Compiler().NewHint(gtHint, 1, lo, modulusLoMinusOne)
	borrow := borrowS[0]
	s.api.AssertIsBoolean(borrow)
	resultLo := s.api.Add(s.api.Sub(modulusLoMinusOne, lo), s.api.Mul(borrow, pow128))
	resultHi := s.api.Sub(s.api.Sub(modulusHi, hi), borrow)
	s.rchk.Check(resultHi, 128)
	s.rchk.Check(resultLo, 128)
}

// the result is NOT rangechecked, but if it is in range, it is canonical
func (s *Skyscraper) canonicalDecompose(v frontend.Variable) []frontend.Variable {
	wordsPerFelt := 32 / s.wordSize
	o, _ := s.api.Compiler().NewHint(wordsBeHint, wordsPerFelt, s.wordSize, v)
	result := make([]frontend.Variable, wordsPerFelt)
	copy(result[:], o)
	s.api.AssertIsEqual(s.varFromWordsBe(result[:]), v)
	s.assertLessThanModulus(s.varFromWordsBe(result[:wordsPerFelt/2]), s.varFromWordsBe(result[wordsPerFelt/2:]))
	return result
}

func (s *Skyscraper) bar(v frontend.Variable) frontend.Variable {
	words := s.canonicalDecompose(v)
	wordsPerFelt := 32 / s.wordSize
	tmp := make([]frontend.Variable, wordsPerFelt/2)
	copy(tmp[:], words[:wordsPerFelt/2])
	copy(words[:], words[wordsPerFelt/2:])
	copy(words[wordsPerFelt/2:], tmp[:])
	for i := range words {
		// sbox implicitly rangechecks the input
		words[i] = s.sbox(words[i])
	}
	return s.varFromWordsBe(words[:])
}

func (s *Skyscraper) Permute(state *[2]frontend.Variable) {
	l, r := state[0], state[1]
	l, r = s.api.Add(r, s.square(l)), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[0]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[1]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[2]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[3]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[4]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[5]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc[6]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc[7]), l
	l, r = s.api.Add(r, s.square(l)), l
	state[0], state[1] = l, r
}

func (s *Skyscraper) Compress(l, r frontend.Variable) frontend.Variable {
	in := [2]frontend.Variable{l, r}
	s.Permute(&in)
	return s.api.Add(l, in[0])
}

func (s *Skyscraper) CompressV2(l, r frontend.Variable) frontend.Variable {
	l_backup := l
	l, r = s.api.Add(r, s.square(l)), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[1]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[2]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[3]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[4]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[5]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc_pow[6]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc_pow[7]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[8]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[9]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc_pow[10]), l
	l, r = s.api.Add(s.api.Add(r, s.bar(l)), s.rc_pow[11]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[12]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[13]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[14]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[15]), l
	l, r = s.api.Add(s.api.Add(r, s.square(l)), s.rc_pow[16]), l
	return s.api.Add(s.api.Add(r, s.square(l)), l_backup)
}
