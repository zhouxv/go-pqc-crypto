package pqc

//NOTE: THE COMMENTS BELOW ARE CODE WHICH GETS COMPILED (THEY ARE CALLED PREAMBLE).IT'S A UNIQUE/WEIRD FEATURE IN CGO.
// ALSO NOTE: THERE MUST BE NO NEWLINE BETWEEN THE END OF THE COMMENT AND THE IMPORT "C" LINE

/*
   #cgo CFLAGS: -Iinclude
   #cgo LDFLAGS: -ldl -loqs -lm

   #include <stdio.h>
   #include <stdlib.h>

   typedef enum {
   	ERR_OK,
   	ERR_CANNOT_LOAD_LIB,
   	ERR_CONTEXT_CLOSED,
   	ERR_MEM,
   	ERR_NO_FUNCTION,
   	ERR_OPERATION_FAILED,
   } libResult;

   #include <oqs/oqs.h>
   #include <dlfcn.h>
   #include <stdbool.h>
   #include <stdlib.h>
   #include <string.h>

   typedef struct {
     void *handle;
   } ctx;

   char *errorString(libResult r) {
   	switch (r) {
   	case ERR_CANNOT_LOAD_LIB:
   		return "cannot load library";
   	case ERR_CONTEXT_CLOSED:
   		return "library closed";
   	case ERR_MEM:
   		return "out of memory";
   	case ERR_NO_FUNCTION:
   		return "library missing required function";
   	case ERR_OPERATION_FAILED:

   		return "operation failed";
   	default:
   		return "unknown error";
   	}
   }

   libResult New(const char *path, ctx **c) {
   	*c = malloc(sizeof(ctx));
   	if (!(*c)) {
   		return ERR_MEM;
   	}
   	(*c)->handle = dlopen(path, RTLD_NOW);
   	if (NULL == (*c)->handle) {
   		free(*c);
   		return ERR_CANNOT_LOAD_LIB;
   	}
   	return ERR_OK;
   }

   libResult SetRandomAlg(const ctx *ctx, const char *name) {
   	OQS_STATUS status = OQS_randombytes_switch_algorithm(name);
   	if (status != OQS_SUCCESS) {
   		return ERR_OPERATION_FAILED;
   	}
   	return ERR_OK;
   }

   libResult GetRandomBytes(uint8_t *buf,int nbytes) {
   	OQS_randombytes(buf,nbytes);

   	return ERR_OK;
   }

   libResult GetSign(const ctx *ctx, const char *name, OQS_SIG **sig) {
   	if (!ctx->handle) {
   		return ERR_CONTEXT_CLOSED;
   	}

   	OQS_SIG *(*func)(const char *);
   	*(void **)(&func) = dlsym(ctx->handle, "OQS_SIG_new");
   	if (NULL == func) {
   		return ERR_NO_FUNCTION;
   	}
   	*sig = (*func)(name);
   	return ERR_OK;
   }

   libResult FreeSig(ctx *ctx, OQS_SIG *sig) {
   	if (!ctx->handle) {
   		return ERR_CONTEXT_CLOSED;
   	}
   	void (*func)(OQS_SIG*);
   	*(void **)(&func) = dlsym(ctx->handle, "OQS_SIG_free");
   	if (NULL == func) {
   		return ERR_NO_FUNCTION;
   	}
   	(*func)(sig);
   	return ERR_OK;
   }

   libResult Close(ctx *ctx) {
   	if (!ctx->handle) {
   		return ERR_CONTEXT_CLOSED;
   	}
   	dlclose(ctx->handle);
   	ctx->handle = NULL;
   	return ERR_OK;
   }

*/
import "C"
import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"strings"
	"sync"
	"unsafe"

	"errors"
)

const (
	AlgNistKat     AlgType = "NIST-KAT"
	defaultLibPath string  = "liboqs.so"
)

// Global package lib singleton
// Only initialized once, protected by mutex
// Should not be accessed outside of GetLib
var packageLib *OQSLib
var libmux sync.Mutex

var errAlreadyClosed = errors.New("already closed")
var errAlgDisabledOrUnknown = errors.New("Signature algorithm is unknown or disabled")
var operationFailed C.libResult = C.ERR_OPERATION_FAILED

func libError(result C.libResult, msg string, a ...interface{}) error {

	if result == C.ERR_OPERATION_FAILED {
		return errors.New("pqclib libError")
	}

	str := C.GoString(C.errorString(result))
	return errors.New(str)
}

type SigType string
type AlgType string

type SecretKey struct {
	Sk []byte
	PublicKey
}

type PublicKey struct {
	Pk  []byte
	Sig OQSSigInfo
}

// Public returns the public key corresponding to priv.
func (priv *SecretKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Equal reports whether priv and x have equivalent values. It ignores
// Precomputed values.
func (priv *SecretKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*SecretKey)
	if !ok {
		return false
	}
	if !priv.PublicKey.Equal(&xx.PublicKey) {
		return false
	}
	if !bytes.Equal(priv.Sk, xx.Sk) {
		return false
	}
	return true
}

func (priv *SecretKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return Sign(*priv, digest)
}

func (p *PublicKey) Equal(pk crypto.PublicKey) bool {
	ppk, ok := pk.(*PublicKey)
	if !ok {
		return false
	}
	return (strings.Compare(string(p.Sig.Algorithm), string(ppk.Sig.Algorithm)) == 0) && (bytes.Equal(p.Pk, ppk.Pk))
}

type OQSSig struct {
	sig *C.OQS_SIG
	ctx *C.ctx
}

type OQSLib struct {
	// C context
	ctx *C.ctx
	// List of enabled signature algorithms, populated by init()
	enabledSigs []SigType
	// List of supported signature algorithms, populated by init()
	supportedSigs []SigType
	// Map of sigtype to OID
	oidMap map[SigType]asn1.ObjectIdentifier
	// Cache of loaded sigs, used by getSig()
	sigMap map[SigType]*OQSSig
}

type OQSSigInfo struct {
	Algorithm SigType
}

const UnknownKeyAlgorithm SigType = "UnknownKeyAlgorithm"

func MaxNumberSigs() int {
	return int(C.OQS_SIG_alg_count())
}

func IsSigEnabled(algName SigType) bool {
	result := C.OQS_SIG_alg_is_enabled(C.CString(string(algName)))
	return result != 0
}

func SigName(algID int) (SigType, error) {
	if algID >= MaxNumberSigs() {
		return "", errors.New("algorithm ID out of range")
	}
	return SigType(C.GoString(C.OQS_SIG_alg_identifier(C.size_t(algID)))), nil
}

func (l *OQSLib) initSigTypes() {
	for i := 0; i < MaxNumberSigs(); i++ {
		sigName, _ := SigName(i)
		l.supportedSigs = append(l.supportedSigs, sigName)
		if IsSigEnabled(sigName) {
			l.enabledSigs = append(l.enabledSigs, sigName)
		}
	}
}

func (l *OQSLib) initSigMap() (err error) {
	for _, sigType := range l.enabledSigs {
		s, err := getSign(l.ctx, sigType)
		if err != nil {
			return errors.New("Unable to load OQS crypto sig")
		}
		l.sigMap[sigType] = s
	}
	return nil

}

func (l *OQSLib) generateOids() {
	for i, sig := range l.enabledSigs {
		l.oidMap[sig] = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 40 + i}
		// fmt.Println(sig, l.oidMap[sig])
		// fmt.Println(sig, l.oidMap[sig])
	}
}

func newLib() (*OQSLib, error) {
	ctx, err := loadCctx(defaultLibPath)
	if err != nil {
		return nil, err
	}
	lib := &OQSLib{
		ctx:           ctx,
		enabledSigs:   []SigType{},
		supportedSigs: []SigType{},
		oidMap:        make(map[SigType]asn1.ObjectIdentifier),
		sigMap:        make(map[SigType]*OQSSig),
	}
	// Using the library variables,
	// initialize the list of available signatures
	lib.initSigTypes()
	// For now, we will also generate oids for those signatures,
	// based on their order in liboqs.
	// Ideally, these OIDs would be specified in liboqs itself.
	lib.generateOids()
	// initialize SigMap
	err = lib.initSigMap()
	if err != nil {
		return nil, errors.New("Failed to initialize liboqs signature algorithms")
	}
	return lib, nil
}

func (l *OQSLib) GetAlgorithmFromOID(oid asn1.ObjectIdentifier) Algorithm {
	for alg, id := range l.oidMap {
		if oid.Equal(id) {
			return alg
		}
	}
	return UnknownKeyAlgorithm
}

func (l *OQSLib) GetAlgorithmIdentifier(alg SigType) (ai pkix.AlgorithmIdentifier, err error) {
	oid, ok := l.oidMap[alg]
	if !ok {
		return ai, errors.New("unknown OQS algorithm name")
	}
	ai.Algorithm = oid
	// The OQS public key algorithms do not require parameters,
	// therefore a NULL parameters value is required.
	ai.Parameters = asn1.NullRawValue
	return ai, nil
}

func (l *OQSLib) Getx509Count(alg SigType) (count int, err error) {
	var pqcAlgo = [...]string{
		"Dilithium2",
		"Dilithium3",
		"Dilithium5",
		"Dilithium2-AES",
		"Dilithium3-AES",
		"Dilithium5-AES",
		"Falcon-512",
		"Falcon-1024",
		"Rainbow-I-Classic",
		"Rainbow-I-Circumzenithal",
		"Rainbow-I-Compressed",
		"Rainbow-III-Classic",
		"Rainbow-III-Circumzenithal",
		"Rainbow-III-Compressed",
		"Rainbow-V-Classic",
		"Rainbow-V-Circumzenithal",
		"Rainbow-V-Compressed",
		"SPHINCS++-Haraka-128f-robust",
		"SPHINCS+-Haraka-128f-simple",
		"SPHINCS+-Haraka-128s-robust",
		"SPHINCS+-Haraka-128s-simple",
		"SPHINCS+-Haraka-192f-robust",
		"SPHINCS+-Haraka-192f-simple",
		"SPHINCS+-Haraka-192s-robust",
		"SPHINCS+-Haraka-192s-simple",
		"SPHINCS+-Haraka-256f-robust",
		"SPHINCS+-Haraka-256f-simple",
		"SPHINCS+-Haraka-256s-robust",
		"SPHINCS+-Haraka-256s-simple",
		"SPHINCS+-SHA256-128f-robust",
		"SPHINCS+-SHA256-128f-simple",
		"SPHINCS+-SHA256-128s-robust",
		"SPHINCS+-SHA256-128s-simple",
		"SPHINCS+-SHA256-192f-robust",
		"SPHINCS+-SHA256-192f-simple",
		"SPHINCS+-SHA256-192s-robust",
		"SPHINCS+-SHA256-192s-simple",
		"SPHINCS+-SHA256-256f-robust",
		"SPHINCS+-SHA256-256f-simple",
		"SPHINCS+-SHA256-256s-robust",
		"SPHINCS+-SHA256-256s-simple",
		"SPHINCS+-SHAKE256-128f-robust",
		"SPHINCS+-SHAKE256-128f-simple",
		"SPHINCS+-SHAKE256-128s-robust",
		"SPHINCS+-SHAKE256-128s-simple",
		"SPHINCS+-SHAKE256-192f-robust",
		"SPHINCS+-SHAKE256-192f-simple",
		"SPHINCS+-SHAKE256-192s-robust",
		"SPHINCS+-SHAKE256-192s-simple",
		"SPHINCS+-SHAKE256-256f-robust",
		"SPHINCS+-SHAKE256-256f-simple",
		"SPHINCS+-SHAKE256-256s-robust",
		"SPHINCS+-SHAKE256-256s-simple",
		"picnic_L1_FS",
		"picnic_L1_UR",
		"picnic_L1_full",
		"picnic_L3_FS",
		"picnic_L3_UR",
		"picnic_L3_full",
		"picnic_L5_FS",
		"picnic_L5_UR",
		"picnic_L5_full",
		"picnic3_L1",
		"picnic3_L3",
		"picnic3_L5",
	}
	for i, v := range pqcAlgo {
		if strings.Compare(v, string(alg)) == 0 {
			return i + 17, nil
		}
	}
	return 0, errors.New(fmt.Sprintf("Signature algorithm [%s] not found", string(alg)))
}

func (l *OQSLib) EnabledSigs() []SigType {
	return l.enabledSigs
}

func (l *OQSLib) GetSig(sigType SigType) (*OQSSig, error) {

	sig, ok := l.sigMap[sigType]
	if !ok {
		return nil, errors.New(fmt.Sprintf("Signature algorithm [%s] not found", string(sigType)))
	}
	return sig, nil
}

func GetLib() (*OQSLib, error) {
	libmux.Lock()
	defer libmux.Unlock()
	if packageLib != nil {
		return packageLib, nil
	}
	lib, err := newLib()
	if err != nil {
		return nil, err
	}
	packageLib = lib
	return packageLib, nil

}

func loadCctx(path string) (*C.ctx, error) {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))

	var ctx *C.ctx
	res := C.New(p, &ctx)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to load module at %q", path)
	}

	return ctx, nil
}

func getSign(ctx *C.ctx, alg SigType) (*OQSSig, error) {
	cStr := C.CString(string(alg))
	defer C.free(unsafe.Pointer(cStr))

	var sigPtr *C.OQS_SIG

	res := C.GetSign(ctx, cStr, &sigPtr)
	if res != C.ERR_OK {
		return nil, libError(res, "failed to get Signature")
	}

	sig := &OQSSig{
		sig: sigPtr,
		ctx: ctx,
	}
	if sig.sig == nil {
		return nil, errAlgDisabledOrUnknown
	}

	return sig, nil
}

//func DestroyLib() (err error) {
//	if packageLib == nil {
//		return nil
//	}
//	err = CloseLib(packageLib)
//	if err == nil {
//		packageLib = nil
//	}
//	return err
//}
//func CloseSig(sig *OQSSig) (error) {
//	if sig == nil {
//		return errAlreadyClosed
//	}
//	res := C.FreeSig(sig.ctx, sig.sig)
//	if res != C.ERR_OK {
//		return libError(res, "failed to free signature")
//	}
//
//	sig.sig = nil
//	return nil
//}
//
//func CloseLib(lib *OQSLib) (error) {
//	res := C.Close(lib.ctx)
//	if res != C.ERR_OK {
//		return libError(res, "failed to close library")
//	}
//	return nil
//}

func setRandomAlg(ctx *C.ctx, strAlg AlgType) (int, error) {
	cStr := C.CString(string(strAlg))
	defer C.free(unsafe.Pointer(cStr))

	res := C.SetRandomAlg(ctx, cStr)

	if res != C.ERR_OK {
		return -1, libError(res, "failed to get Alg")
	}

	return 1, nil
}

func GetRandomBytes(nbytes int) (randombytes []byte, err error) {
	bytes := C.malloc(C.ulong(nbytes))
	defer C.free(unsafe.Pointer(bytes))

	res := C.GetRandomBytes((*C.uint8_t)(bytes), C.int(nbytes))

	if res != C.ERR_OK {
		return nil, libError(res, "failed to set bytes")
	}

	return C.GoBytes(bytes, C.int(nbytes)), nil
}
