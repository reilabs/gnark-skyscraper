package skyscraper

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func bigIntFromString(s string) frontend.Variable {
	var res big.Int
	res.SetString(s, 10)
	return res
}

type TestSboxC struct {
	WordSize int
	In, Out  frontend.Variable
}

func (c *TestSboxC) Define(api frontend.API) error {
	s := NewSkyscraper(api, c.WordSize)
	api.AssertIsEqual(s.sbox(c.In), c.Out)
	return nil
}

func TestSbox(t *testing.T) {
	assert := test.NewAssert(t)
	for wordSize := 1; wordSize <= 2; wordSize++ {
		assert.CheckCircuit(&TestSboxC{WordSize: wordSize}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
			test.WithValidAssignment(&TestSboxC{wordSize, 0xcd, 0xd3}),
			test.WithValidAssignment(&TestSboxC{wordSize, 0x17, 0x0e}),
			test.WithInvalidAssignment(&TestSboxC{wordSize, 0x17, 0x0f}),
			test.WithInvalidAssignment(&TestSboxC{wordSize, 0x1234, 0x0f}))
	}
	assert.CheckCircuit(&TestSboxC{WordSize: 2}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		test.WithValidAssignment(&TestSboxC{2, 0xcd17, 0xd30e}))
}

type TestSquareC struct {
	In, Out frontend.Variable
}

func (c *TestSquareC) Define(api frontend.API) error {
	s := NewSkyscraper(api, 1)
	s.sbox(123) // needed to silence an error about unused lookup tables
	api.AssertIsEqual(s.square(c.In), c.Out)
	return nil
}

func TestSquare(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&TestSquareC{}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
		test.WithValidAssignment(&TestSquareC{0, 0}),
		test.WithInvalidAssignment(&TestSquareC{0, 1}),
		test.WithValidAssignment(&TestSquareC{1, bigIntFromString("9915499612839321149637521777990102151350674507940716049588462388200839649614")}),
		test.WithValidAssignment(&TestSquareC{2, bigIntFromString("17773755579518009376303681366703133516854333631346829854655645366227550102839")}),
		test.WithValidAssignment(&TestSquareC{bigIntFromString("1104450765605124869545290932753078120560901577733272073477890658487831733222"), bigIntFromString("20498050724266033890829404465405035543297153733520482423774420418741549228506")}))
}

type TestBarC struct {
	WordSize int
	In, Out  frontend.Variable
}

func (c *TestBarC) Define(api frontend.API) error {
	s := NewSkyscraper(api, c.WordSize)
	api.AssertIsEqual(s.bar(c.In), c.Out)
	return nil
}

func TestBar(t *testing.T) {
	assert := test.NewAssert(t)
	for wordSize := 1; wordSize <= 2; wordSize++ {
		assert.CheckCircuit(&TestBarC{WordSize: wordSize}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
			test.WithValidAssignment(&TestBarC{wordSize, 0, 0}),
			test.WithValidAssignment(&TestBarC{wordSize, 1, bigIntFromString("680564733841876926926749214863536422912")}),
			test.WithValidAssignment(&TestBarC{wordSize, 2, bigIntFromString("1361129467683753853853498429727072845824")}),
			test.WithValidAssignment(&TestBarC{wordSize, bigIntFromString("4111585712030104139416666328230194227848755236259444667527487224433891325648"), bigIntFromString("18867677047139790809471719918880601980605904427073186248909139907505620573990")}))

	}
}

type TestCompressC struct {
	WordSize      int
	In1, In2, Out frontend.Variable
}

func (c *TestCompressC) Define(api frontend.API) error {
	s := NewSkyscraper(api, c.WordSize)
	api.AssertIsEqual(s.Compress(c.In1, c.In2), c.Out)
	return nil
}

func TestCompress(t *testing.T) {
	assert := test.NewAssert(t)
	for wordSize := 1; wordSize <= 2; wordSize++ {
		assert.CheckCircuit(&TestCompressC{WordSize: wordSize}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16),
			test.WithValidAssignment(&TestCompressC{wordSize,
				bigIntFromString("21614608883591910674239883101354062083890746690626773887530227216615498812963"),
				bigIntFromString("9813154100006487150380270585621895148484502414032888228750638800367218873447"),
				bigIntFromString("3583228880285179354728993622328037400470978495633822008876840172083178912457")}))
	}

}
