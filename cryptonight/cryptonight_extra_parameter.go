// Copyright 2017-2018 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package cryptonight

//import "fmt"
import "unsafe"

import "encoding/binary"
import "github.com/aead/skein"
import "github.com/dchest/blake256"

// see this commit https://github.com/monero-project/monero/commit/e136bc6b8a480426f7565b721ca2ccf75547af62#diff-7000dc02c792439471da62856f839d62
func cryptonight_extra_parameter(input []byte, variant int) []byte {

	var dummy [256]byte
	var S [25]uint64

	var key1 [64]uint32
	var key2 [64]uint32

	var a [2]uint64
	var b [2]uint64
	var c [2]uint64

	
	a_uint32 := (*(*[4]uint32)(unsafe.Pointer(&a[0])))[:len(a)*2]
	//b_uint32 := (*(*[4]uint32)(unsafe.Pointer(&b[0])))[:len(b)*2]
	c_uint32 := (*(*[4]uint32)(unsafe.Pointer(&c[0])))[:len(c)*2]

	// same array is accessed as 3 different ways, buts it bettter than copying
	var ScratchPad = make([]uint64, 1<<18, 1<<18)
	ScratchPad_uint32 := (*(*[MAX_ARRAY_LIMIT]uint32)(unsafe.Pointer(&ScratchPad[0])))[:len(ScratchPad)*2]
	// ScratchPad_byte := (*(*[MAX_ARRAY_LIMIT]byte)(unsafe.Pointer(&ScratchPad[0])))[:len(ScratchPad)*8]

	copy(dummy[:], input)

	for i := 0; i < 16; i++ {
		S[i] = binary.LittleEndian.Uint64(dummy[i<<3:])
	}
	S[16] = 0x8000000000000000

	keccakf(&S)

	// lets convert everything back to bytes
	for i := 0; i < 25; i++ {
		binary.LittleEndian.PutUint64(dummy[i<<3:], S[i])
	}

	// extract keys
	/*for i := 0 ; i <8;i++{
	    key1[i] = binary.LittleEndian.Uint32(dummy[i<<2:])
	    key2[i] = binary.LittleEndian.Uint32(dummy[32+(i<<2):])
	}*/

	expandKeyGo(dummy[0:32], key1[:], nil)
	expandKeyGo(dummy[32:64], key2[:], nil)

	/* for i :=0; i< 60;i++{
	         fmt.Printf("%2d %X\n", i, key2[i])
	}*/

	// var text [128]byte
	var text_uint32 [32]uint32
	//copy(text[:],dummy[64:64+128]) // copy 128 bytes

	for i := 0; i < 32; i++ {
		text_uint32[i] = binary.LittleEndian.Uint32(dummy[64+(i<<2):])
	}

	
	/* for i :=0; i< 32;i++{
	         fmt.Printf("%2d %X  i  %08X %08X\n", i, text_uint32[i] , key1[i],key1[i<<1])
	}*/

	for i := 0; i < 0x4000; i++ {
		for j := 0; j < 8; j++ {
			CNAESTransform((text_uint32[(j << 2):]), key1[:])
		}

		//memcpy(CNCtx.Scratchpad + (i << 4), text, 128);
		copy(ScratchPad_uint32[i*32:], text_uint32[:])
	}

	a[0] = S[0] ^ S[4]
	a[1] = S[1] ^ S[5]
	b[0] = S[2] ^ S[6]
	b[1] = S[3] ^ S[7]


	// the big slow round
	for i := 0; i < 0x80000; i++ {
		// {
		c[0] = ScratchPad[((a[0]&0x1FFFF0)>>3)+0]
		c[1] = ScratchPad[((a[0]&0x1FFFF0)>>3)+1]

		CNAESRnd(c_uint32, a_uint32)

		b[0] ^= c[0]
		b[1] ^= c[1]

		    ScratchPad[((a[0]&0x1FFFF0)>>3)+0] = b[0]
			ScratchPad[((a[0]&0x1FFFF0)>>3)+1] = b[1]
		

		b[0] = ScratchPad[((c[0]&0x1FFFF0)>>3)+0]
		b[1] = ScratchPad[((c[0]&0x1FFFF0)>>3)+1]

		// time to do 64 bit * 64 bit multiply
		var lower64, upper64 uint64
		{

			x := c[0]
			y := b[0]

			a := x >> 32
			b := x & 0xffffffff
			c := y >> 32
			d := y & 0xffffffff

			ac := a * c
			bc := b * c
			ad := a * d
			bd := b * d

			mid34 := (bd >> 32) + (bc & 0xffffffff) + (ad & 0xffffffff)

			upper64 = ac + (bc >> 32) + (ad >> 32) + (mid34 >> 32)
			lower64 = (mid34 << 32) | (bd & 0xffffffff)
			_ = lower64
			_ = upper64

		}

		a[1] += lower64
		a[0] += upper64

		ScratchPad[((c[0]&0x1FFFF0)>>3)+0] = a[0]
		ScratchPad[((c[0]&0x1FFFF0)>>3)+1] = a[1]



		a[0] ^= b[0]
		a[1] ^= b[1]

		b[0] = c[0]
		b[1] = c[1]

	}

	// fmt.Printf(" a %X %X\n", a[0],a[1]);
	// fmt.Printf(" b %X %X\n", b[0],b[1]);

	for i := 0; i < 32; i++ {
		text_uint32[i] = binary.LittleEndian.Uint32(dummy[64+(i<<2):])
	}

	for i := 0; i < 0x4000; i++ {

		for j := 0; j < 32; j++ {
			text_uint32[j] ^= ScratchPad_uint32[(i*32)+j]

		}
		for j := 0; j < 8; j++ {
			CNAESTransform((text_uint32[(j << 2):]), key2[:])
		}

	}

	/*for i :=0; i< 32;i++{
	         fmt.Printf("%2d %X\n", i, text_uint32[i])
	}*/

	for i := 0; i < 32; i++ {
		binary.LittleEndian.PutUint32(dummy[64+(i<<2):], text_uint32[i])
	}

	for i := 8; i < 25; i++ {
		S[i] = binary.LittleEndian.Uint64(dummy[i<<3:])
	}

	keccakf(&S) // do the keccak round
	/* for i :=0; i< 25;i++{
	         fmt.Printf("S %02d %X\n", i, S[i])
	}*/

	// lets convert everything back to bytes
	for i := 0; i < 25; i++ {
		binary.LittleEndian.PutUint64(dummy[i<<3:], S[i])
	}

	var resulthash []byte

	switch S[0] & 3 {

	case 0:
		// fmt.Printf("blake\n")

		// blake
		blakehash := blake256.New()
		blakehash.Write(dummy[:200])
		resulthash = blakehash.Sum(nil) //matching

	case 1: // groestl
		// fmt.Printf("groestl not implemented\n")
		var output [32]byte
		var input = dummy[:200]
		crypto_hash(output[:], input, uint64(len(input)))
		resulthash = output[:]
	case 2: // jh
		//fmt.Printf("jh not implemented\n")

		myjhash := NewJhash256()
		myjhash.Write(dummy[:200])
		resulthash = myjhash.Sum(nil)

	case 3: // skein
		//  fmt.Printf("skein\n")
		skeinhash := skein.New256(nil)
		skeinhash.Write(dummy[:200])
		resulthash = skeinhash.Sum(nil) //matchin

	}

	//fmt.Printf("result hash %x\n", resulthash)

	return resulthash

}

func SlowHash_extra_parameter(msg []byte) []byte {
	hash := cryptonight_extra_parameter(append(msg, byte(0x01)), 1)
	return hash
}


