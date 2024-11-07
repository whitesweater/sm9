///************************************************************************
// File name: SM9_enc_dec.c
// Version: SM9_enc_dec_V1.0
// Date: Dec 29,2016
// Description: implementation of SM9 encryption algorithm and decryption algorithm
// all operations based on BN curve line function
// Function List:
// 1.bytes128_to_ecn2 //convert 128 bytes into ecn2
// 2.zzn12_ElementPrint //print all element of struct zzn12
// 3.ecn2_Bytes128_Print //print 128 bytes of ecn2
// 4.LinkCharZzn12 //link two different types(unsigned char and zzn12)to one(unsigned char)
// 5.Test_Point //test if the given point is on SM9 curve
// 6.SM4_Block_Encrypt //encrypt the message with padding,according to PKS#5
// 7.SM4_Block_Decrypt //decrypt the cipher with padding,according to PKS#5
// 8.SM9_H1 //function H1 in SM9 standard 5.4.2.2
// 9.SM9_Enc_MAC //MAC in SM9 standard 5.4.5
// 10.SM9_Init //initiate SM9 curve
// 11.SM9_GenerateEncryptKey //generate encrypted private and public key
// 12.SM9_Encrypt //SM9 encryption algorithm
// 13.SM9_Decrypt //SM9 decryption algorithm
// 14.SM9_SelfCheck() //SM9 slef-check
//
// Notes:
// This SM9 implementation source code can be used for academic, non-profit making or non - commercial use only.
// This SM9 implementation is created on MIRACL. SM9 implementation source code provider does 
//not provide MIRACL library, MIRACL license or any permission to use MIRACL library.Any commercial
//use of MIRACL requires a license which may be obtained from Shamus Software Ltd.
//**************************************************************************/
#include"miracl.h"
#include "SM9_enc_dec.h"
#include "KDF.h"
#include "SM4.h"
#include"R-ate.h"
#include"zzn12_operation.h"
#include <stdlib.h>


extern miracl* mip;
extern zzn2 X; //Frobniues constant
/****************************************************************
 Function: bytes128_to_ecn2
 Description: convert 128 bytes into ecn2
 Calls: MIRACL functions
 Calls: MIRACL functions
 Called By: SM9_Init,SM9_Decrypt
 Input: Ppubs[]
 Output: ecn2 *res
 Return: FALSE: execution error
 TRUE: execute correctly
 Others:
****************************************************************/
BOOL bytes128_to_ecn2(unsigned char Ppubs[], ecn2* res)
{
	zzn2 x, y;
	big a, b;
	ecn2 r;
	r.x.a = mirvar(0); r.x.b = mirvar(0);
	r.y.a = mirvar(0); r.y.b = mirvar(0);
	r.z.a = mirvar(0); r.z.b = mirvar(0);
	r.marker = MR_EPOINT_INFINITY;
	x.a = mirvar(0); x.b = mirvar(0);
	y.a = mirvar(0); y.b = mirvar(0);
	a = mirvar(0); b = mirvar(0);
	bytes_to_big(BNLEN, Ppubs, b);
	bytes_to_big(BNLEN, Ppubs + BNLEN, a);
	zzn2_from_bigs(a, b, &x);
	bytes_to_big(BNLEN, Ppubs + BNLEN * 2, b);
	bytes_to_big(BNLEN, Ppubs + BNLEN * 3, a);
	zzn2_from_bigs(a, b, &y);
	return ecn2_set(&x, &y, res);
}
/****************************************************************
 Function: zzn12_ElementPrint
 Description: print all element of struct zzn12
 Calls: MIRACL functions
 Called By: SM9_Encrypt,SM9_Decrypt
 Input: zzn12 x
 Output: NULL
 Return: NULL
 Others:
****************************************************************/

void zzn12_ElementPrint(zzn12 x)
{
	big tmp;
	tmp = mirvar(0);
	redc(x.c.b.b, tmp); cotnum(tmp, stdout);
	redc(x.c.b.a, tmp); cotnum(tmp, stdout);
	redc(x.c.a.b, tmp); cotnum(tmp, stdout);
	redc(x.c.a.a, tmp); cotnum(tmp, stdout);
	redc(x.b.b.b, tmp); cotnum(tmp, stdout);
	redc(x.b.b.a, tmp); cotnum(tmp, stdout);
	redc(x.b.a.b, tmp); cotnum(tmp, stdout);
	redc(x.b.a.a, tmp); cotnum(tmp, stdout);
	redc(x.a.b.b, tmp); cotnum(tmp, stdout);
	redc(x.a.b.a, tmp); cotnum(tmp, stdout);
	redc(x.a.a.b, tmp); cotnum(tmp, stdout);
	redc(x.a.a.a, tmp); cotnum(tmp, stdout);
}
/****************************************************************
 Function: ecn2_Bytes128_Print
 Description: print 128 bytes of ecn2
 Calls: MIRACL functions
 Called By: SM9_Encrypt,SM9_Decrypt
 Input: ecn2 x
 Output: NULL
 Return: NULL
 Others:
****************************************************************/
void ecn2_Bytes128_Print(ecn2 x)
{
	big tmp;
	tmp = mirvar(0);
	redc(x.x.b, tmp); cotnum(tmp, stdout);
	redc(x.x.a, tmp); cotnum(tmp, stdout);
	redc(x.y.b, tmp); cotnum(tmp, stdout);
	redc(x.y.a, tmp); cotnum(tmp, stdout);
}
/****************************************************************
 Function: LinkCharZzn12
 Description: link two different types(unsigned char and zzn12)to one(unsigned char)
 Calls: MIRACL functions
 Called By: SM9_Encrypt,SM9_Decrypt
 Input: message:
 len: length of message
 w: zzn12 element
 Output: Z: the characters array stored message and w
 Zlen: length of Z
 Return: NULL
 Others:
****************************************************************/
void LinkCharZzn12(unsigned char* message, int len, zzn12 w, unsigned char* Z, int Zlen)
{
	big tmp;
	tmp = mirvar(0);
	memcpy(Z, message, len);
	redc(w.c.b.b, tmp); big_to_bytes(BNLEN, tmp, Z + len, 1);
	redc(w.c.b.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN, 1);
	redc(w.c.a.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 2, 1);
	redc(w.c.a.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 3, 1);
	redc(w.b.b.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 4, 1);
	redc(w.b.b.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 5, 1);
	redc(w.b.a.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 6, 1);
	redc(w.b.a.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 7, 1);
	redc(w.a.b.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 8, 1);
	redc(w.a.b.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 9, 1);
	redc(w.a.a.b, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 10, 1);
	redc(w.a.a.a, tmp); big_to_bytes(BNLEN, tmp, Z + len + BNLEN * 11, 1);
}

/****************************************************************
 Function: GT_to_G1
 Description: H2函数映射
 Calls: MIRACL functions
 Called By: SM9_Encrypt
 Input: message:
 len: length of message
 w: zzn12 element
 Output: Z: the characters array stored message and w
 Zlen: length of Z
 Return: NULL
 Others:
****************************************************************/
epoint* GT_to_G1(zzn12 h) {
	epoint* g1 = epoint_init();

	// 示例转换逻辑，具体实现需要根据实际需求调整
	// 这部分逻辑需要根据你的库的实际情况来实现
	// 假设我们有某种映射函数
	big x = mirvar(0);
	big y = mirvar(0);

	// 伪代码：将 GT 类型的某些值映射到 G1 的坐标
	// 需要根据实际的库函数实现转换
	//例如：zzn12_get(gt, x, y); // 假设存在这样的函数
	//epoint_set(x, y, 0, g1);
	
	// 清理

	big tmp, total;
	tmp = mirvar(0);
	total = mirvar(0);
	add(h.a.a.a, h.a.b.a, x);
	add(x, h.b.a.a, x);
	add(x, h.b.b.a, x);
	add(x, h.c.a.a, x);
	add(x, h.c.b.a, x);

	add(h.a.a.b, h.a.b.b, y);
	add(y, h.b.a.b, y);
	add(y, h.b.b.b, y);
	add(y, h.c.a.b, y);
	add(y, h.c.b.b, y);

	epoint_set(x, y, 0, g1);

	return g1;
}
/****************************************************************
 Function: Test_Point
 Description: test if the given point is on SM9 curve
 Calls:
 Called By: SM9_Decrypt
 Input: point
 Output: null
 Return: 0: success
 1: not a valid point on curve
 Others:
****************************************************************/
int Test_Point(epoint* point)
{
	big x, y, x_3, tmp;
	epoint* buf;
	x = mirvar(0); y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);
	buf = epoint_init();
	//test if y^2=x^3+b
	epoint_get(point, x, y);
	power(x, 3, para_q, x_3); //x_3=x^3 mod p
	multiply(x, para_a, x);
	divide(x, para_q, tmp);
	add(x_3, x, x); //x=x^3+ax+b
	add(x, para_b, x);
	divide(x, para_q, tmp); //x=x^3+ax+b mod p
	power(y, 2, para_q, y); //y=y^2 mod p
	if (mr_compare(x, y) != 0)
		return 1;
	//test infinity
	ecurve_mult(N, point, buf);
	if (point_at_infinity(buf) == FALSE)
		return 1;
	return 0;
}


/***************************************************************
 Function: SM4_Block_Encrypt
 Description: encrypt the message with padding,according to PKS#5
 Calls: SM4_Encrypt
 Called By: SM9_Encrypt
 Input:
 key:the key of SM4
 message:data to be encrypted
 mlen: the length of message
 Output:
 cipher: ciphertext
 cipher_len:the length of ciphertext
 Return: NULL
 Others:
****************************************************************/
void SM4_Block_Encrypt(unsigned char key[], unsigned char* message, int mlen, unsigned char
	* cipher, int* cipher_len)
{
	unsigned char mess[16];
	int i, rem = mlen % 16;
	for (i = 0; i < mlen / 16; i++)
		SM4_Encrypt(key, &message[i * 16], &cipher[i * 16]);
	//encrypt the last block
	memset(mess, 16 - rem, 16);
	if (rem)
		memcpy(mess, &message[i * 16], rem);
	SM4_Encrypt(key, mess, &cipher[i * 16]);
}
/***************************************************************
 Function: SM4_Block_Decrypt
 Description: decrypt the cipher with padding,according to PKS#5
 Calls: SM4_Decrypt
 Called By: SM9_Decrypt
 Input:
 key:the key of SM4
 cipher: ciphertext
 mlen: the length of ciphertext
 Output:
 plain: plaintext
 plain_len:the length of plaintext
 Return: NULL
 Others:
****************************************************************/
void SM4_Block_Decrypt(unsigned char key[], unsigned char* cipher, int len, unsigned char
	* plain, int* plain_len)
{
	int i;
	for (i = 0; i < len / 16; i++)
		SM4_Decrypt(key, cipher + i * 16, plain + i * 16);
	*plain_len = len - plain[len - 1];
}


/****************************************************************
 Function: SM9_H1
 Description: function H1 in SM9 standard 5.4.2.2
 Calls: MIRACL functions,SM3_KDF
 Called By: SM9_Encrypt
 Input: Z:
 Zlen:the length of Z
 n:Frobniues constant X
 Output: h1=H1(Z,Zlen)
 Return: 0: success;
 1: asking for memory error
 Others:
****************************************************************/
int SM9_H1(unsigned char Z[], int Zlen, big n, big h1)
{
	int hlen, i, ZHlen;
	big hh, i256, tmp, n1;
	unsigned char* ZH = NULL, * ha = NULL;
	hh = mirvar(0); i256 = mirvar(0);
	tmp = mirvar(0); n1 = mirvar(0);
	convert(1, i256);
	ZHlen = Zlen + 1;
	hlen = (int)ceil((5.0 * logb2(n)) / 32.0);
	decr(n, 1, n1);
	ZH = (char*)malloc(sizeof(char) * (ZHlen + 1));
	if (ZH == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(ZH + 1, Z, Zlen);
	ZH[0] = 0x01;
	ha = (char*)malloc(sizeof(char) * (hlen + 1));
	if (ha == NULL) return SM9_ASK_MEMORY_ERR;
	SM3_KDF(ZH, ZHlen, hlen, ha);
	for (i = hlen - 1; i >= 0; i--)//key[???С] 
	{
		premult(i256, ha[i], tmp);
		add(hh, tmp, hh);
		premult(i256, 256, i256);
		divide(i256, n1, tmp);
		divide(hh, n1, tmp);
	}
	incr(hh, 1, h1);
	free(ZH); free(ha);
	return 0;
}
/****************************************************************
 Function: SM9_Enc_MAC
 Description: MAC in SM9 standard 5.4.5
 Calls: SM3_256
 Called By: SM9_Encrypt,SM9_Decrypt
 Input:
 K:key
 Klen:the length of K
 M:message
 Mlen:the length of message
 Output: C=MAC(K,Z)
 Return: 0: success;
 1: asking for memory error
 Others:
****************************************************************/
int SM9_Enc_MAC(unsigned char* K, int Klen, unsigned char* M, int Mlen, unsigned char C[])
{
	unsigned char* Z = NULL;
	int len = Klen + Mlen;
	Z = (char*)malloc(sizeof(char) * (len + 1));
	if (Z == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(Z, M, Mlen);
	memcpy(Z + Mlen, K, Klen);
	SM3_256(Z, len, C);
	free(Z);
	return 0;
}
/****************************************************************
 Function: SM9_Init
 Description: Initiate SM9 curve
 Calls: MIRACL functions
 Called By: SM9_SelfCheck
 Input: null
 Output: null
 Return: 0: success;
 5: base point P1 error
 6: base point P2 error
 Others:
****************************************************************/
int SM9_Init()
{
	big P1_x, P1_y, r;
	mip = mirsys(1000, 16);
	mip->IOBASE = 16;
	r = mirvar(1);
	para_q = mirvar(0); N = mirvar(0);
	P1_x = mirvar(0); P1_y = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0); para_t = mirvar(0);
	X.a = mirvar(0); X.b = mirvar(0);
	P2.x.a = mirvar(0); P2.x.b = mirvar(0);
	P2.y.a = mirvar(0); P2.y.b = mirvar(0);
	P2.z.a = mirvar(0); P2.z.b = mirvar(0);
	P2.marker = MR_EPOINT_INFINITY;
	P2p.x.a = mirvar(0); P2p.x.b = mirvar(0);
	P2p.y.a = mirvar(0); P2p.y.b = mirvar(0);
	P2p.z.a = mirvar(0); P2p.z.b = mirvar(0);
	P2p.marker = MR_EPOINT_INFINITY;
	P1 = epoint_init();
	bytes_to_big(BNLEN, SM9_q, para_q);
	bytes_to_big(BNLEN, SM9_P1x, P1_x);
	bytes_to_big(BNLEN, SM9_P1y, P1_y);
	bytes_to_big(BNLEN, SM9_a, para_a);
	bytes_to_big(BNLEN, SM9_b, para_b);
	bytes_to_big(BNLEN, SM9_N, N);
	bytes_to_big(BNLEN, SM9_t, para_t);
	mip->TWIST = MR_SEXTIC_M;
	zzn12_init(&generater);
	ecurve_init(para_a, para_b, para_q, MR_PROJECTIVE); //Initialises GF(q) elliptic curve
	//MR_PROJECTIVE specifying projective coordinates
	if (!epoint_set(P1_x, P1_y, 0, P1)) return SM9_G1BASEPOINT_SET_ERR;
	if (!(bytes128_to_ecn2(SM9_P2, &P2))) return SM9_G2BASEPOINT_SET_ERR;

	if (!(bytes128_to_ecn2(SM9_P2, &P2p))) return SM9_G2BASEPOINT_SET_ERR;
	ecn2_mul(r, &P2p);
	set_frobenius_constant(&X);
	return 0;
}
/***************************************************************
 Function: SM9_GenerateEncryptKey
 Description: Generate encryption keys(public key and private key)
 Calls: MIRACL functions,SM9_H1,xgcd,ecn2_Bytes128_Print
 Called By: SM9_SelfCheck
 Input: hid:0x03
 ID:identification
 IDlen:the length of ID
 ke:master private key used to generate encryption public key and private key
 Output: Ppubs:encryption public key
 deB: encryption private key
 Return: 0: success;
 1: asking for memory error
 Others:
****************************************************************/
int SM9_GenerateEncryptKey(unsigned char hid[], unsigned char* ID, int IDlen, big ke, unsigned char
	Ppubs[], unsigned char deB[])
{
	big h1, t1, t2, rem, xPpub, yPpub, tmp;
	unsigned char* Z = NULL;
	int Zlen = IDlen + 1, buf;
	ecn2 dEB;
	epoint* Ppub;
	h1 = mirvar(0); t1 = mirvar(0);
	t2 = mirvar(0); rem = mirvar(0); tmp = mirvar(0);
	xPpub = mirvar(0); yPpub = mirvar(0);
	Ppub = epoint_init();
	dEB.x.a = mirvar(0); dEB.x.b = mirvar(0); dEB.y.a = mirvar(0); dEB.y.b = mirvar(0);
	dEB.z.a = mirvar(0); dEB.z.b = mirvar(0); dEB.marker = MR_EPOINT_INFINITY;
	Z = (char*)malloc(sizeof(char) * (Zlen + 1));
	memcpy(Z, ID, IDlen);
	memcpy(Z + IDlen, hid, 1);
	buf = SM9_H1(Z, Zlen, N, h1);
	if (buf != 0) return buf;
	add(h1, ke, t1);//t1=H1(IDA||hid,N)+ke  in SM9-RBPRE,ke=\alpha
	xgcd(t1, N, t1, t1, t1);//t1=t1(-1)
	multiply(ke, t1, t2); divide(t2, N, rem);//t2=ks*t1(-1) t1\t2 are the same as those in SM9 algorithm
	//Ppub=[ke]P1
	ecurve_mult(ke, P1, Ppub);
	//deB=[t2]P2
	ecn2_copy(&P2, &dEB);
	ecn2_mul(t2, &dEB);
	printf("\n**************The private key deB = (xdeB, ydeB)??*********************\n");
	ecn2_Bytes128_Print(dEB);
	printf("\n**********************PublicKey Ppubs=[ke]P1??*************************\n");
	epoint_get(Ppub, xPpub, yPpub);
	cotnum(xPpub, stdout); cotnum(yPpub, stdout);
	epoint_get(Ppub, xPpub, yPpub);
	big_to_bytes(BNLEN, xPpub, Ppubs, 1);
	big_to_bytes(BNLEN, yPpub, Ppubs + BNLEN, 1);

	printf("dfdddddddddddddddddddddd:::     %s", Ppubs);
	for (int bb = 0; bb < 64; bb++) {
		printf("%c", Ppubs[bb]);
	}
	big x, y;
	x = mirvar(0);
	y = mirvar(0);
	epoint* Ppube;
	Ppube = epoint_init();
	bytes_to_big(BNLEN, Ppubs, x);
	bytes_to_big(BNLEN, Ppubs + BNLEN, y);
	epoint_set(x, y, 0, Ppube);
	if (!ecap(P2, Ppube, para_t, X, &generater)) return SM9_MY_ECAP_12A_ERR;

	redc(dEB.x.b, tmp); big_to_bytes(BNLEN, tmp, deB, 1);
	redc(dEB.x.a, tmp); big_to_bytes(BNLEN, tmp, deB + BNLEN, 1);
	redc(dEB.y.b, tmp); big_to_bytes(BNLEN, tmp, deB + BNLEN * 2, 1);
	redc(dEB.y.a, tmp); big_to_bytes(BNLEN, tmp, deB + BNLEN * 3, 1);
	free(Z);
	return 0;
}
/****************************************************************
 Function: SM9_Encrypt
 Description: SM9 encryption algorithm
 Calls: MIRACL functions,zzn12_init(),ecap(),member(),zzn12_ElementPrint(),
 zzn12_pow(),LinkCharZzn12(),SM3_KDF(),SM9_Enc_MAC(),SM4_Block_Encrypt()
 Called By: SM9_SelfCheck()
 Input:
 hid:0x03
 IDB //identification of userB
 message //the message to be encrypted
 len //the length of message
 rand //a random number K lies in [1,N-1]
 EncID //encryption identification,0:stream cipher 1:block cipher
 k1_len //the byte length of K1 in block cipher algorithm
 k2_len //the byte length of K2 in MAC algorithm
 Ppubs //encrtption public key
 Output: C //cipher C1||C3||C2
 Clen //the byte length of C
 Return:
 0: success

 1: asking for memory error
 2: element is out of order q
 3: R-ate calculation error
 A: K1 equals 0
 Others:
****************************************************************/
int SM9_Encrypt(unsigned char hid[], unsigned char* IDB, unsigned char* message, int mlen, unsigned
	char rand[],
	int EncID, int k1_len, int k2_len, unsigned char Ppub[], unsigned char C[], unsigned char B[], int
	* C_len, int* B_len, big ke)
{
	big h, x, y, r;
	zzn12 w;
	epoint* Ppube, * QB, * C1;
	unsigned char* Z = NULL, * K = NULL, * C2 = NULL, * C3 = NULL, C4[SM3_len / 8], * Z2 = NULL;
	int i = 0, j = 0, Zlen, buf, klen, B2_len;

	epoint* B1;
	ecn2 B2;
	unsigned char *B3=NULL, B4[SM3_len/8];
	int B3_len;

	//initiate
	h = mirvar(0); r = mirvar(0); x = mirvar(0); y = mirvar(0);
	QB = epoint_init(); Ppube = epoint_init(); C1 = epoint_init();
	zzn12_init(&w);
	bytes_to_big(BNLEN, Ppub, x);
	bytes_to_big(BNLEN, Ppub + BNLEN, y);
	epoint_set(x, y, 0, Ppube);
	B2.x.a = mirvar(0); B2.x.b = mirvar(0); B2.y.a = mirvar(0); B2.y.b = mirvar(0);
	B2.z.a = mirvar(0); B2.z.b = mirvar(0); B2.marker = MR_EPOINT_INFINITY;
	B1 = epoint_init();

	//Step1:randnom
	bytes_to_big(BNLEN, rand, r);
	printf("\n***********************randnom r:********************************\n");
	cotnum(r, stdout);

	//Step1:calculate QB=[H1(IDB||hid,N)]P1+Ppube /calculate B1=r(H1(ID||hid,N)+\alpha)\cdot P1 B2=rP2
	big mult_add;
	mult_add = mirvar(0);
	Zlen = strlen(IDB) + 1;
	Z = (char*)malloc(sizeof(char) * (Zlen + 1));
	if (Z == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(Z, IDB, strlen(IDB));
	memcpy(Z + strlen(IDB), hid, 1);
	buf = SM9_H1(Z, Zlen, N, h);//H1(ID||hid,N)
	if (buf) return buf;
	add(h, ke, mult_add); //H1(ID||hid,N)+\alpha
	ecurve_mult(mult_add, P1, B1);//H1(ID||hid,N+\alpha)P1
	ecurve_mult(r, B1, B1);//r(H1(ID||hid,N)+\alpha)P1
	printf("\n*******************C1=r(H1(ID||hid,N)+alpha)\cdot P1*****************\n");
	epoint_get(B1, x, y);
	cotnum(x, stdout); cotnum(y, stdout);
	big_to_bytes(BNLEN, x, B, 1); big_to_bytes(BNLEN, y, B + BNLEN, 1);//copy B1 to B
	
	//Step1-2: B2=rP2
	ecn2_copy(&P2p, &B2);
	ecn2_mul(r, &B2);
	printf("\n**************B2 = r\cdot P2p*********************\n");
	ecn2_Bytes128_Print(P2p);

	big_to_bytes(BNLEN, B2.x.a, B + BNLEN * 2, 1);
	big_to_bytes(BNLEN, B2.x.b, B + BNLEN * 3, 1);
	big_to_bytes(BNLEN, B2.y.a, B + BNLEN * 4, 1);
	big_to_bytes(BNLEN, B2.y.b, B + BNLEN * 5, 1);//B2拼接

	//Step1-3: w=g^r
	w = zzn12_pow(generater, r);
	printf("\n***************************w=g^r:**********************************\n");
	zzn12_ElementPrint(w);
	free(Z);

	//Step2:K=KDF(C1||C2||w||ID,klen)  Step:6-1: calculate K=KDF(C1||w||IDB,klen)
	B3_len = mlen;
	*B_len = BNLEN * 6 + SM3_len / 8 + B3_len;
	klen = k1_len + k2_len;
	Zlen = strlen(IDB) + BNLEN * 18;//the size of IDB and other component space 
	Z2 = (char*)malloc(sizeof(char) * (Zlen + 1));
	K = (char*)malloc(sizeof(char) * (klen + 1));//compute the size of klen and one another space
	B3 = (char*)malloc(sizeof(char) * (mlen + 1));
	if (Z2 == NULL || K == NULL || B3 == NULL) return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(B, BNLEN * 6, w, Z2, Zlen - strlen(IDB));//link the parameters
	memcpy(Z2 + BNLEN * 18, IDB, strlen(IDB));//copy IDB to Z+.. and the length of IDB computed by str(IDB)
	SM3_KDF(Z2, Zlen, klen, K);//整合到K上,KDF
	printf("\n*****************K=KDF(C1||C2||w||ID,klen):***********************\n");
	for (i = 0; i < klen; i++) printf("%02x", K[i]);
	

	//Step3-1:C3=m异或K1  and test if K1==0?
	for (i = 0; i < mlen; i++)
	{
		if (K[i] == 0) j = j + 1;
		B3[i] = message[i] ^ K[i];
	}
	if (j == k1_len) return SM9_ERR_K1_ZERO;
	printf("\n************************* B3=M^K1 :***************************\n");
	B2_len = mlen;
	for (i = 0; i < B2_len; i++) printf("%02x", B3[i]);
	//Step3-2:B4=MAC(K2,B3)
	SM9_Enc_MAC(K + k1_len, k2_len, B3, mlen, B4);
	printf("\n********************** B4=MAC(K2,B3):*************************\n");
	for (i = 0; i < 32; i++) printf("%02x", B4[i]);
	
	//Step4: B=(B1,B2,B3,B4)  在此之前已经完成了B=(B1,B2)
	memcpy(B + BNLEN * 6, B3, B3_len);//B3_len到底等于多少 待定
	memcpy(B + BNLEN * 6 + B3_len, B4, SM3_len / 8);
	free(K);
	free(B3);
	free(Z2);
	return 0;
}
/****************************************************************
 Function:SM9_ReKeyGen
 Description: SM9 KeyReGeneration algorithm
 Calls: MIRACL functions,zzn12_init(),Test_Point(), ecap(),
 member(),zzn12_ElementPrint(),LinkCharZzn12(),SM3_KDF(),
 SM9_Enc_MAC(),SM4_Block_Decrypt(),bytes128_to_ecn2()
 Called By: SM9_SelfCheck()
 Input:
 C //cipher C1||C3||C2
 C_len //the byte length of C
 deB //private key of user B
 IDB //identification of userB
 EncID //encryption identification,0:stream cipher 1:block cipher
 k1_len //the byte length of K1 in block cipher algorithm
 k2_len //the byte length of K2 in MAC algorithm
 Output:
 M //message
 Mlen: //the length of message
 Return:
 0: success
 1: asking for memory error
 2: element is out of order q
 3: R-ate calculation error
 4: test if C1 is on G1
 A: K1 equals 0
 B: compare error of C3
 Others:
****************************************************************/
int SM9_ReKeyGen(unsigned char hid[], unsigned char* IDB, unsigned char* message, int mlen, unsigned
	char rand[], unsigned
	char rand2[],
	int EncID, int k1_len, int k2_len, unsigned char deB[], unsigned char C[], unsigned char B[], unsigned char rk[],
	unsigned char rkp[], big ke, int max_mem,int k, unsigned char S[], int S_single[]) {//k为最大撤销量，l为实际撤销量，n为用户数量,S为所有用户id集合
	big t, s, h, x, y;
	unsigned char* Z = NULL;
	int Zlen, buf, mult;
	zzn12 sigma;

	h = mirvar(0);
	s = mirvar(0);
	t = mirvar(0);
	x = mirvar(0);
	y = mirvar(0);
	zzn12_init(&sigma);

	//Step1:randnom s,t
	bytes_to_big(BNLEN, rand, t);
	printf("\n***********************randnum t:********************************\n");
	cotnum(t, stdout);
	bytes_to_big(BNLEN, rand2, s);
	printf("\n***********************randnum s:********************************\n");
	cotnum(s, stdout);

	//Step1-2:choose \sigma   already done in SM9_init and has been defined in SM9_enc_dec.h

	//Step2:compute rk1i
	ecn2 rk1, rk2; // 存储ecn2类型的参数rk1
	epoint* rk4, * rk6,* tmp2, *rk3;
	zzn12 rk5, tmp;
	zzn12_init(&tmp);
	zzn12_init(&rk5);
	rk4 = epoint_init();
	rk6 = epoint_init();
	tmp2 = epoint_init();
	rk3 = epoint_init();
	rk1.x.a = mirvar(0); rk1.x.b = mirvar(0); rk1.y.a = mirvar(0); rk1.y.b = mirvar(0);
	rk1.z.a = mirvar(0); rk1.z.b = mirvar(0); rk1.marker = MR_EPOINT_INFINITY;
	rk2.x.a = mirvar(0); rk2.x.b = mirvar(0); rk2.y.a = mirvar(0); rk2.y.b = mirvar(0);
	rk2.z.a = mirvar(0); rk2.z.b = mirvar(0); rk2.marker = MR_EPOINT_INFINITY;

	ecn2_copy(&P2p, &rk1);//rk1=P2
	ecn2_mul(s, &rk1);//first compute rk1=sP2
	ecn2 rk1i;
	rk1i.x.a = mirvar(0); rk1i.x.b = mirvar(0); rk1i.y.a = mirvar(0); rk1i.y.b = mirvar(0);
	rk1i.z.a = mirvar(0); rk1i.z.b = mirvar(0); rk1i.marker = MR_EPOINT_INFINITY;
	ecn2_copy(&rk1, &rk1i);
	for (int i = 0; i < k + 1; i++) {
		int flag = i + 2;
		// 将rk1复制到rk1i中,方便循环运算
		if (flag != 0) {
			ecn2_mul(ke, &rk1i);// rk1=sP2 alpha 
			flag--;
		}
		big_to_bytes(BNLEN, rk1i.x.a, rk + BNLEN * (4 * i ), 1);
		big_to_bytes(BNLEN, rk1i.x.b, rk + BNLEN * (4 * i + 1), 1);
		big_to_bytes(BNLEN, rk1i.y.a, rk + BNLEN * (4 * i + 2), 1);
		big_to_bytes(BNLEN, rk1i.y.b, rk + BNLEN * (4 * i + 3), 1);//每一次计算完rk1i后都复制到rk中
	}//rk1计算并复制到rk中

	//Step3:Compute rk2=t·P2p+skid
	ecn2_copy(&P2p, &rk2);
	ecn2_mul(t, &rk2);
	ecn2 dEB;
	dEB.x.a = mirvar(0); dEB.x.b = mirvar(0); dEB.y.a = mirvar(0); dEB.y.b = mirvar(0);
	dEB.z.a = mirvar(0); dEB.z.b = mirvar(0); dEB.marker = MR_EPOINT_INFINITY;
	bytes128_to_ecn2(deB, &dEB);
	ecn2_add(&dEB, &rk2);//把deb中的先复制到rk2便于后续复盘
	printf("\n**************rk2=t·P2p+skid*********************\n");
	ecn2_Bytes128_Print(rk2);
	big_to_bytes(BNLEN, rk2.x.a, rk + BNLEN * (4 * (k + 1)), 1);
	big_to_bytes(BNLEN, rk2.x.b, rk + BNLEN * (4 * (k + 1) + 1), 1);
	big_to_bytes(BNLEN, rk2.y.a, rk + BNLEN * (4 * (k + 1) + 2), 1);
	big_to_bytes(BNLEN, rk2.y.b, rk + BNLEN * (4 * (k + 1) + 3), 1);


	//Step4:rk3=alpha t P1
	ecurve_mult(t, P1, rk3);
	ecurve_mult(ke, rk3, rk3);
	big_to_bytes(BNLEN, rk3->X, rk + BNLEN * (4 * (k + 1) + 4), 1);
	big_to_bytes(BNLEN, rk3->Y, rk + BNLEN * (4 * (k + 1) + 5), 1);

	//Step5:rk4=t·H1(ID||hid,N)·P1+H2(sigma)
	ecurve_mult(t, P1, rk4);
	Zlen = strlen(IDB) + 1;
	Z = (char*)malloc(sizeof(char) * (Zlen + 1));
	if (Z == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(Z, IDB, strlen(IDB));
	memcpy(Z + strlen(IDB), hid, 1);
	buf = SM9_H1(Z, Zlen, N, h);//H1(ID||hid,N)
	if (buf) return buf;
	ecurve_mult(h,rk4, rk4);//mult the result of H1 to rk4
	free(Z);
	
	if (!ecap(P2, P1, para_t, X, &sigma)) return SM9_MY_ECAP_12A_ERR;
	//Step5-2:compute H2(sigma)
	tmp2 = GT_to_G1(sigma);
	ecurve2_add(tmp2, rk4);
	big_to_bytes(BNLEN, rk4->X, rk + BNLEN * (4 * (k + 1) + 6), 1);
	big_to_bytes(BNLEN, rk4->Y, rk + BNLEN * (4 * (k + 1) + 7), 1);

	//Step6:compute rk5=g^{s}·sigma
	tmp = zzn12_pow(generater, s);
	zzn12_mul(tmp, sigma, &rk5);
	big_to_bytes(BNLEN, rk5.a.a.a, rk + BNLEN * (4 * (k + 1) + 8), 1);
	big_to_bytes(BNLEN, rk5.a.a.b, rk + BNLEN * (4 * (k + 1) + 9), 1);
	big_to_bytes(BNLEN, rk5.a.b.a, rk + BNLEN * (4 * (k + 1) + 10), 1);
	big_to_bytes(BNLEN, rk5.a.b.b, rk + BNLEN * (4 * (k + 1) + 11), 1);
	big_to_bytes(BNLEN, rk5.b.a.a, rk + BNLEN * (4 * (k + 1) + 12), 1);
	big_to_bytes(BNLEN, rk5.b.a.b, rk + BNLEN * (4 * (k + 1) + 13), 1);
	big_to_bytes(BNLEN, rk5.b.b.a, rk + BNLEN * (4 * (k + 1) + 14), 1);
	big_to_bytes(BNLEN, rk5.b.b.b, rk + BNLEN * (4 * (k + 1) + 15), 1);
	big_to_bytes(BNLEN, rk5.c.a.a, rk + BNLEN * (4 * (k + 1) + 16), 1);
	big_to_bytes(BNLEN, rk5.c.a.b, rk + BNLEN * (4 * (k + 1) + 17), 1);
	big_to_bytes(BNLEN, rk5.c.b.a, rk + BNLEN * (4 * (k + 1) + 18), 1);
	big_to_bytes(BNLEN, rk5.c.b.b, rk + BNLEN * (4 * (k + 1) + 19), 1);
	
	//Step7:rk6=s·累乘(H1(IDi||hid,N)+alpha)·P1
	ecurve_mult(s, P1, rk6);
	unsigned char ID[1000];
	big tmp_6, mult_h;
	mult_h = mirvar(0);
	tmp_6 = mirvar(1);
	int tmp1 = 0, tmpa = 0, j;
	printf("*******************The set of data receivers' identification*************\n");
	for (int i = 0; i < k; i++) {
		Zlen = S_single[i] + 1;
		tmp1 = S_single[i];
		for (j = 0; j < tmp1; j++) {
			ID[j] = S[j + tmpa];
		}
		for (j = 0; j < tmp1; j++) {
			printf("%c", ID[j]);
		}
		printf("\n");
		tmpa += S_single[i];
		Z = (char*)malloc(sizeof(char) * (Zlen + 1));
		if (Z == NULL) return SM9_ASK_MEMORY_ERR;
		memcpy(Z, ID, tmp1);
		memcpy(Z + tmp1, hid, 1);
		h = mirvar(0);
		//printf("%s\n", Z);
		SM9_H1(Z, Zlen, N, h);//H1(ID||hid,N)
		copy(h, mult_h);
		multiply(h, tmp_6, tmp_6);
		free(Z);
	}
	add(tmp_6, ke, tmp_6);//H1(ID||hid,N)P1+\alpha
	ecurve_mult(tmp_6, rk6, rk6);//r(H1(ID||hid,N)P1+\alpha)
	big_to_bytes(BNLEN, rk6->X, rk + BNLEN * (4 * (k + 1) + 20), 1);
	big_to_bytes(BNLEN, rk6->Y, rk + BNLEN * (4 * (k + 1) + 21), 1);

	return 0;
}
/****************************************************************
 Function:generate_multiplicative_polynomial
 多项式生成函数，生成F（x）
 */
int * generate_multiplicative_polynomial(unsigned char hid[], int l,unsigned char R[], int R_single[]) {// l为实际撤销量，R为待撤销用户id集合
	big* roots = malloc(l * sizeof(big));

	// 初始化根
	for (int i = 0; i < l; i++) {
		roots[i] = mirvar(0);
		bigrand(mip->modulus, roots[i]); // 初始化、生成随机根
	}

	// 计算多项式系数
	//Step1:Compute H1(ID'||hid,N)的累乘
	big h1;
	int Zlen, buf;
	unsigned char* Z = NULL;
	unsigned char* ID[1000];
	big mult_f1;
	h1 = mirvar(0);
	mult_f1 = mirvar(1);
	//先提取R[]中的值并且依次使用
	int tmp1 = 0, tmpa = 0, j;
	//Compute 累乘H1(IDp||hid,N)
	for (int i = 0; i < l; i++) {
		Zlen = R_single[i] + 1;
		tmp1 = R_single[i];
		for (j = 0; j < tmp1; j++) {
			ID[j] = R[j + tmpa];
		}
		tmpa += R_single[i];
		Z = (char*)malloc(sizeof(char) * (Zlen + 1));
		if (Z == NULL)return SM9_ASK_MEMORY_ERR;
		memcpy(Z, ID, tmp1);
		memcpy(Z + tmp1, hid, 1);
		SM9_H1(Z, Zlen, N, h1);
		roots[i] = h1;
		multiply(h1,mult_f1,mult_f1);
	}

	xgcd(mult_f1, N, mult_f1, mult_f1, mult_f1);//求逆，计算mult_f1累乘的逆


	big coefficients[50], temp;
	for (int i = 0; i < l+1; i++) {
		coefficients[i] = mirvar(0);
	} // 初始化 系数数组
	coefficients[0] = mirvar(1);
	temp = mirvar(0);
	for (int i = 0; i < l; i++) {
		for (int j = i + 1; j > 0; j--) {
			multiply(coefficients[j - 1], roots[i], temp);
			add(coefficients[j-1], temp, coefficients[j]);
		}
		multiply(coefficients[0], roots[i], coefficients[0]);
	}

	for (int i = 0; i < l; i++)
	{
		multiply(mult_f1, coefficients[i], coefficients[i]);
	}
	// 打印多项式
	printf("F(x) = ");
	for (int i = l; i >= 0; i--) {
		if (size(coefficients[i]) != 0) {
			cotnum(coefficients[i], stdout);
			if (i > 0) {
				printf("x^%d + ", i);
			}
		}
	}
	printf("\n");

	return coefficients;//返回系数指针

	// 清理
	for (int i = 0; i < l; i++) {
		mirkill(roots[i]);
	}
	for (int i = 0; i < l; i++) {
		mirkill(coefficients[i]);
	}
	free(roots);
	free(coefficients);

}
/*
* Function: big_to_ecn2
* Description: turnu from big into ecn2
*/
void bytes_to_ecn2(unsigned char* rk, ecn2 r[], int l) {

	zzn2 x, y;
	big a, b;
	x.a = mirvar(1); x.b = mirvar(1);
	y.a = mirvar(1); y.b = mirvar(1);
	a = mirvar(0); b = mirvar(0);

	for (int i = 0; i < l+1; i++) {
		bytes_to_big(BNLEN, rk + BNLEN * (4 * i    ), a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * i + 1), b);
		copy(a, x.a);
		copy(b, x.b);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * i + 2), a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * i + 3), b);
		copy(a, y.a);
		copy(b, y.b);
		ecn2_set(&x, &y, &r[i]);
		ecn2_Bytes128_Print(r[i]);
	}
	return 0;
}

/****************************************************************
 Function:SM9_Revoke
 Description: SM9 KeyReGeneration algorithm
 Calls: MIRACL functions,zzn12_init(),Test_Point(), ecap(),
 member(),zzn12_ElementPrint(),LinkCharZzn12(),SM3_KDF(),
 SM9_Enc_MAC(),SM4_Block_Decrypt(),bytes128_to_ecn2()
 Called By: SM9_SelfCheck()
 Input:
 C //cipher C1||C3||C2
 C_len //the byte length of C
 deB //private key of user B
 IDB //identification of userB
 EncID //encryption identification,0:stream cipher 1:block cipher
 k1_len //the byte length of K1 in block cipher algorithm
 k2_len //the byte length of K2 in MAC algorithm
 Output:
 M //message
 Mlen: //the length of message
 Return:
 0: success
 1: asking for memory error
 2: element is out of order q
 3: R-ate calculation error
 4: test if C1 is on G1
 A: K1 equals 0
 B: compare error of C3
 Others:
****************************************************************/
int SM9_Revoke(unsigned char hid[], unsigned char* IDB, unsigned char* message, int mlen, unsigned
	char rand[],
	int EncID, int k1_len, int k2_len, unsigned char C[], unsigned char B[], 
	unsigned char *rk, unsigned char* rkp, int
	* C_len, big ke, int k, int l, unsigned char S[],unsigned char R[], int R_single[]) {//k为最大撤销量，l为实际撤销量，n为用户数量,S为所有用户id集合，R为待撤销用户id集合
	big F1, F2, F, h;
	F1 = mirvar(0);
	F2 = mirvar(0);
	F = mirvar(0);
	h = mirvar(0);
	int Zlen, buf;
	unsigned char* Z = NULL;

	//Step1:调用函数生成F(x)并输出
	int* f = generate_multiplicative_polynomial(hid, l, R, R_single);

	//Step2-1:Compute Rk1'=
	//get rk1i to rk1pt
	big rk1t[50];
	for (int i = 0; i <= 4l; i++) {
		rk1t[i] = mirvar(0);
	}//循环初始化
	for (int i = 0; i <= 4l; i++) {
		bytes_to_big(BNLEN, rk + BNLEN * i, rk1t[i]);//there are l+1 numbers in rk1t
	}
	ecn2 rk1pt[20], rk1p;
	for (int i = 0; i < l+1; i++) {
		rk1pt[i].x.a = mirvar(0);
		rk1pt[i].x.b = mirvar(0);
		rk1pt[i].y.a = mirvar(0);
		rk1pt[i].y.b = mirvar(0);
		rk1pt[i].z.a = mirvar(0);
		rk1pt[i].z.b = mirvar(0);
		rk1pt[i].marker = MR_EPOINT_INFINITY;//由于rk1i中存储了i个不同的值，需要用数组存储
	}
	rk1p.x.a = mirvar(0);
	rk1p.x.b = mirvar(0);
	rk1p.y.a = mirvar(0);
	rk1p.y.b = mirvar(0);
	rk1p.z.a = mirvar(0);
	rk1p.z.b = mirvar(0);
	rk1p.marker = MR_EPOINT_INFINITY;//初始化rk1p，用来存储fi-1同rk1i相乘的值

	//从rk中将rk1pt提取出来，放入rk1pt中
	bytes_to_ecn2(rk, &rk1pt, l);

	//Compute rk1p=fi-1*rk1p
	for (int i = 0; i < l + 1; i++) {
		ecn2_mul(f[i], &rk1pt[i]);//实际上f[0]是常数项，但是rk11实际上存储在rk1pt[0]中，所以f[0]对上rk11
		ecn2_add(&rk1pt[i], &rk1p);
	}

	//Step2*2:Compute rk5p=rk5乘上e的双线性配对
	zzn12 rk5p, rk5t;
	zzn12_init(&rk5p);
	zzn12_init(&rk5t);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 8), rk5t.a.a.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 9), rk5t.a.a.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 10), rk5t.a.a.b);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 11), rk5t.a.b.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 12), rk5t.a.a.b);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 13), rk5t.b.a.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 14), rk5t.b.a.b);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 15), rk5t.b.b.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 16), rk5t.b.a.b);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 17), rk5t.c.a.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 18), rk5t.c.b.a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 19), rk5t.c.a.b);//将k中rk5的值复制到rk5t中

	ecn2 rk5pp;
	rk5pp.x.a = mirvar(0);
	rk5pp.x.b = mirvar(0);
	rk5pp.y.a = mirvar(0);
	rk5pp.y.b = mirvar(0);
	rk5pp.z.a = mirvar(0);
	rk5pp.z.b = mirvar(0);
	rk5pp.marker = MR_EPOINT_INFINITY;//由于rk1i中存储了i个不同的值，需要用数组存储
	
	//计算双线性配对
	//先计算fi和rk1i相乘
	for (int i = 1; i <l; i++) {
		ecn2_mul(f[i], &rk1pt[i-1]);
		ecn2_add(&rk1pt[i-1], &rk5pp);
	}
	ecap(rk5pp, P1, para_t, X, &rk5p);
	if (!ecap(rk5pp, P1, para_t, X, &rk5p)) return SM9_MY_ECAP_12A_ERR;
	zzn12_mul(rk5t, rk5p, &rk5p);//rk5p=rk5·e(P1,累加fi·rk1i)

 	//Compute rk6p
	epoint* rk6p;
	rk6p = epoint_init();
	big h1;
	unsigned char ID[1000];
	big mult_f1;
	h1 = mirvar(0);
	h = mirvar(0);
	mult_f1 = mirvar(1);

	//Compute 累乘H1(IDp||hid,N)
	int tmp1 = 0, tmpa = 0, j;
	for (int i = 0; i < l; i++) {
		Zlen = R_single[i] + 1;
		tmp1 = R_single[i];
		for (j = 0; j < tmp1; j++) {
			ID[j] = R[j + tmpa];
		}
		for (j = 0; j < tmp1; j++) {
			printf("%c", ID[j]);
		}
		printf("\n");
		tmpa += R_single[i];
		Z = (char*)malloc(sizeof(char) * (Zlen + 1));
		if (Z == NULL) return SM9_ASK_MEMORY_ERR;
		memcpy(Z, ID, tmp1);
		memcpy(Z + tmp1, hid, 1);
		SM9_H1(Z, Zlen, N, h1);
		multiply(h1, mult_f1, mult_f1);
	}

	xgcd(mult_f1, N, mult_f1, mult_f1, mult_f1);//计算完成rk中系数的逆
	
	//get rk6;
	big x, y;
	x = mirvar(0);
	y = mirvar(0);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 20), x);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * k + 21), y);
	epoint_set(x, y, 0, rk6p);

	ecurve_mult(mult_f1,rk6p,rk6p);

	//进行rkp的复制

	big_to_bytes(BNLEN, rk1p.x.a, rkp, 1);
	big_to_bytes(BNLEN, rk1p.x.b, rkp + BNLEN, 1);
	big_to_bytes(BNLEN, rk1p.y.a, rkp + BNLEN * 2, 1);
	big_to_bytes(BNLEN, rk1p.y.b, rkp + BNLEN * 3, 1);//进行rk1p的复制

	memcpy(rkp + BNLEN * 4, rk + BNLEN * (4 * (k + 1)), BNLEN * 8);//完成rk2,rk3,rk4的复制

	big_to_bytes(BNLEN, rk5p.a.a.a, rkp + BNLEN * 12, 1);
	big_to_bytes(BNLEN, rk5p.a.a.b, rkp + BNLEN * 13, 1);
	big_to_bytes(BNLEN, rk5p.a.b.a, rkp + BNLEN * 14, 1);
	big_to_bytes(BNLEN, rk5p.a.b.b, rkp + BNLEN * 15, 1);
	big_to_bytes(BNLEN, rk5p.b.a.a, rkp + BNLEN * 16, 1);
	big_to_bytes(BNLEN, rk5p.b.a.b, rkp + BNLEN * 17, 1);
	big_to_bytes(BNLEN, rk5p.b.b.a, rkp + BNLEN * 18, 1);
	big_to_bytes(BNLEN, rk5p.b.b.b, rkp + BNLEN * 19, 1);
	big_to_bytes(BNLEN, rk5p.c.a.a, rkp + BNLEN * 20, 1);
	big_to_bytes(BNLEN, rk5p.c.a.b, rkp + BNLEN * 21, 1);
	big_to_bytes(BNLEN, rk5p.c.b.a, rkp + BNLEN * 22, 1);
	big_to_bytes(BNLEN, rk5p.c.b.b, rkp + BNLEN * 23, 1);//完成rk5的复制

	big_to_bytes(BNLEN, rk6p->X, rkp + BNLEN * 24, 1);
	big_to_bytes(BNLEN, rk6p->Y, rkp + BNLEN * 25, 1);///完成rk6的复制

	return 0;

}
/****************************************************************
 Function: SM9_ReDecrypt
 Description: SM9 ReDecryption algorithm*/
int SM9_ReEncrycrypt(unsigned char hid[], unsigned char* IDB, unsigned char* message, unsigned char rk[], unsigned char CT[],
	unsigned char rkp[], int mlen, unsigned
	char rand[],
	int EncID, int k1_len, int k2_len, unsigned char Ppub[], unsigned char C[], unsigned char B[], int
	* C_len, int* B_len, big ke, int k, int* CT_len)
{
	ecn2 C1p, C2p, C2;
	epoint* C4p, * C6p,* C1;
	zzn12 C3p, C3pt1, C3pt2, C5p;
	unsigned char* Z = NULL, * K = NULL;
	C1p.x.a = mirvar(0);
	C1p.x.b = mirvar(0);
	C1p.y.a = mirvar(0);
	C1p.y.b = mirvar(0);
	C1p.z.a = mirvar(0);
	C1p.z.b = mirvar(0);
	C1p.marker = MR_EPOINT_INFINITY;

	C2p.x.a = mirvar(0);
	C2p.x.b = mirvar(0);
	C2p.y.a = mirvar(0);
	C2p.y.b = mirvar(0);
	C2p.z.a = mirvar(0);
	C2p.z.b = mirvar(0);
	C2p.marker = MR_EPOINT_INFINITY;

	C2.x.a = mirvar(0);
	C2.x.b = mirvar(0);
	C2.y.a = mirvar(0);
	C2.y.b = mirvar(0);
	C2.z.a = mirvar(0);
	C2.z.b = mirvar(0);
	C2.marker = MR_EPOINT_INFINITY;

	C4p = epoint_init();
	C6p = epoint_init();
	C1 = epoint_init();

	zzn12_init(&C3pt1);
	zzn12_init(&C3pt2);
	zzn12_init(&C3p);
	zzn12_init(&C5p);

	//先计算C3pt1=e(rk2,C1),C3pt2=e(rk3,C2)-1
	//Get C1
	big x, y;
	x = mirvar(0);
	y = mirvar(0);
	bytes_to_big(BNLEN, B, x);
	bytes_to_big(BNLEN, B + BNLEN , y);
	epoint_set(x, y, 1, C1);

	//Get C2 ecn2 C2
	zzn2 m, n;
	big a, b;
	m.a = mirvar(0); m.b = mirvar(0);
	n.a = mirvar(0); n.b = mirvar(0);
	a = mirvar(0); b = mirvar(0);

	bytes_to_big(BNLEN, B + BNLEN * 2, a);
	bytes_to_big(BNLEN, B + BNLEN * 3, b);
	copy(a, m.a);
	copy(b, m.b);
	bytes_to_big(BNLEN, B + BNLEN * 4, a);
	bytes_to_big(BNLEN, B + BNLEN * 5, b);
	copy(a, n.a);
	copy(b, n.b);
	ecn2_set(&m, &n, &C2);

	//Get rk2
	ecn2 rk2;
	rk2.x.a = mirvar(0);
	rk2.x.b = mirvar(0);
	rk2.y.a = mirvar(0);
	rk2.y.b = mirvar(0);
	rk2.z.a = mirvar(0);
	rk2.z.b = mirvar(0);
	rk2.marker = MR_EPOINT_INFINITY;
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1)), a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 1), b);
	copy(a, m.a);
	copy(b, m.b);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 2), a);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 3), b);
	copy(a, n.a);
	copy(b, n.b);
	//int ab = 9;
	zzn2_copy(&m, &rk2.x);
	zzn2_copy(&n, &rk2.y);
	//ab=ecn2_set(&m, &n, &rk2);
	//printf("\n%d", ab);

	//Get rk3
	epoint* rk3;
	rk3 = epoint_init();
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 4), x);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 5), y);
	epoint_set(x, y, 1, rk3);

	//Compute C3pt1=e(rk2,C1)
	big s, t;
	s = mirvar(0);
	t = mirvar(0);
	int p = 5;
	p=epoint_get(C1, s, t);
	cotnum(s, stdout); cotnum(t, stdout);
	p=ecap(rk2, C1, para_t, X, &C3pt1);
	printf("*************************Test wheather C3pt1 is computed correctly!**************************");
	printf("\nC3pt1:%d\n", p);

	//Compute C3pt2=e(rk3,C2)-1
	epoint* Fp;//far point 
	Fp = epoint_init();
	p = 6;
	ecurve_sub(rk3, Fp);//通过无穷远点减去rk3的方式计算逆
	p=ecap(C2, rk3, para_t, X, &C3pt2);
	printf("*************************Test wheather C3pt2 is computed correctly!**************************");
	printf("\nC3pt2:%d\n", p);

	//Start Copy
	//C1p
	if (rkp == NULL) {
		bytes_to_big(BNLEN, rk, a);
		bytes_to_big(BNLEN, rk + BNLEN * 1, b);
		copy(a, m.a);
		copy(b, m.b);
		bytes_to_big(BNLEN, rk + BNLEN * 2, a);
		bytes_to_big(BNLEN, rk + BNLEN * 3, b);
		copy(a, n.a);
		copy(b, n.b);
		ecn2_set(&m, &n, &C1p);
	}
	else {
		bytes_to_big(BNLEN, rkp, a);
		bytes_to_big(BNLEN, rkp + BNLEN * 1, b);
		copy(a, m.a);
		copy(b, m.b);
		bytes_to_big(BNLEN, rkp + BNLEN * 2, a);
		bytes_to_big(BNLEN, rkp + BNLEN * 3, b);
		copy(a, n.a);
		copy(b, n.b);
		zzn2_copy(&m, &C1p.x);
		zzn2_copy(&n, &C1p.y);
	}

	//C2p
	ecn2_copy(&C2, &C2p);

	//C3p
	zzn12_mul(C3pt1, C3pt2, &C3p);

	//C4p
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 6), x);
	bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 7), y);
	epoint_set(x, y, 0, C4p);

	//C5p
	if (rkp == NULL) {//如果rkp为空，需要从rk中提取rk5
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 8), C5p.a.a.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 9), C5p.a.a.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 10), C5p.a.a.b);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 11), C5p.a.b.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 12), C5p.a.a.b);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 13), C5p.b.a.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 14), C5p.b.a.b);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 15), C5p.b.b.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 16), C5p.b.a.b);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 17), C5p.c.a.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 18), C5p.c.b.a);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 19), C5p.c.a.b);
	}
	else {//如果p不为空，需要从rkp中提取，因此同上述的提取不太一样
		bytes_to_big(BNLEN, rkp + BNLEN * 16, C5p.a.a.a);
		bytes_to_big(BNLEN, rkp + BNLEN * 17, C5p.a.a.b);
		bytes_to_big(BNLEN, rkp + BNLEN * 18, C5p.a.b.a);
		bytes_to_big(BNLEN, rkp + BNLEN * 19, C5p.a.a.b);
		bytes_to_big(BNLEN, rkp + BNLEN * 20, C5p.b.a.a);
		bytes_to_big(BNLEN, rkp + BNLEN * 21, C5p.b.a.b);
		bytes_to_big(BNLEN, rkp + BNLEN * 22, C5p.b.b.a);
		bytes_to_big(BNLEN, rkp + BNLEN * 23, C5p.b.a.b);
		bytes_to_big(BNLEN, rkp + BNLEN * 24, C5p.c.a.a);
		bytes_to_big(BNLEN, rkp + BNLEN * 25, C5p.c.a.b);
		bytes_to_big(BNLEN, rkp + BNLEN * 26, C5p.c.b.a);
		bytes_to_big(BNLEN, rkp + BNLEN * 27, C5p.c.a.b);
	}

	//C6p
	if (rkp == NULL) {//如果rkp为空，需要从rk中提取rk6
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 20), x);
		bytes_to_big(BNLEN, rk + BNLEN * (4 * (k + 1) + 21), y);
		epoint_set(x, y, 0, C6p);
	}
	else {//如果p不为空，需要从rkp中提取，因此同上述的提取不太一样
		bytes_to_big(BNLEN, rkp + BNLEN * 28, x);
		bytes_to_big(BNLEN, rkp + BNLEN * 29, y); 
		epoint_set(x, y, 0, C6p);
	}

	//C7p、C8p、C9p直接从B中复制
	//Copy
	big_to_bytes(BNLEN, C1p.x.a, CT, 1);
	big_to_bytes(BNLEN, C1p.x.b, CT + BNLEN * 1, 1);
	big_to_bytes(BNLEN, C1p.y.a, CT + BNLEN * 2, 1);
	big_to_bytes(BNLEN, C1p.y.b, CT + BNLEN * 3, 1);//C1p

	big_to_bytes(BNLEN, C2p.x.a, CT + BNLEN * 4, 1);
	big_to_bytes(BNLEN, C2p.x.b, CT + BNLEN * 5, 1);
	big_to_bytes(BNLEN, C2p.y.a, CT + BNLEN * 6, 1);
	big_to_bytes(BNLEN, C2p.y.b, CT + BNLEN * 7, 1);//C2p

	big_to_bytes(BNLEN, C3p.a.a.a, CT + BNLEN * 8, 1);
	big_to_bytes(BNLEN, C3p.a.a.b, CT + BNLEN * 9, 1);
	big_to_bytes(BNLEN, C3p.a.b.a, CT + BNLEN * 10, 1);
	big_to_bytes(BNLEN, C3p.a.b.b, CT + BNLEN * 11, 1);
	big_to_bytes(BNLEN, C3p.b.a.a, CT + BNLEN * 12, 1);
	big_to_bytes(BNLEN, C3p.b.a.b, CT + BNLEN * 13, 1);
	big_to_bytes(BNLEN, C3p.b.b.a, CT + BNLEN * 14, 1);
	big_to_bytes(BNLEN, C3p.b.b.b, CT + BNLEN * 15, 1);
	big_to_bytes(BNLEN, C3p.c.a.a, CT + BNLEN * 16, 1);
	big_to_bytes(BNLEN, C3p.c.a.b, CT + BNLEN * 17, 1);
	big_to_bytes(BNLEN, C3p.c.b.a, CT + BNLEN * 18, 1);
	big_to_bytes(BNLEN, C3p.c.b.b, CT + BNLEN * 19, 1);//C3p

	big_to_bytes(BNLEN, C4p->X, CT + BNLEN * 20, 1);
	big_to_bytes(BNLEN, C4p->Y, CT + BNLEN * 21, 1);//C4p

	big_to_bytes(BNLEN, C5p.a.a.a, CT + BNLEN * 22, 1);
	big_to_bytes(BNLEN, C5p.a.a.b, CT + BNLEN * 23, 1);
	big_to_bytes(BNLEN, C5p.a.b.a, CT + BNLEN * 24, 1);
	big_to_bytes(BNLEN, C5p.a.b.b, CT + BNLEN * 25, 1);
	big_to_bytes(BNLEN, C5p.b.a.a, CT + BNLEN * 26, 1);
	big_to_bytes(BNLEN, C5p.b.a.b, CT + BNLEN * 27, 1);
	big_to_bytes(BNLEN, C5p.b.b.a, CT + BNLEN * 28, 1);
	big_to_bytes(BNLEN, C5p.b.b.b, CT + BNLEN * 29, 1);
	big_to_bytes(BNLEN, C5p.c.a.a, CT + BNLEN * 30, 1);
	big_to_bytes(BNLEN, C5p.c.a.b, CT + BNLEN * 31, 1);
	big_to_bytes(BNLEN, C5p.c.b.a, CT + BNLEN * 32, 1);
	big_to_bytes(BNLEN, C5p.c.b.b, CT + BNLEN * 33, 1);//C5p

	big_to_bytes(BNLEN, C6p->X, CT + BNLEN * 34, 1);
	big_to_bytes(BNLEN, C6p->Y, CT + BNLEN * 35, 1);//C6p

	epoint_get(C1, s, t);

	big_to_bytes(BNLEN, s, CT + BNLEN * 36, 1);
	big_to_bytes(BNLEN, t, CT + BNLEN * 37, 1);//C7

	memcpy(CT + BNLEN * 38, B + BNLEN * 6, mlen);
	memcpy(CT + BNLEN * 38 + mlen, B + BNLEN * 6 + mlen, SM3_len / 8);

	*CT_len = BNLEN * 38 + mlen + SM3_len / 8;

	return 0;
}

/****************************************************************
 Function: SM9_Decrypt 未经过重加密的解密算法
 Description: SM9 Decryption algorithm
 Calls: MIRACL functions,zzn12_init(),Test_Point(), ecap(),
 member(),zzn12_ElementPrint(),LinkCharZzn12(),SM3_KDF(),
 SM9_Enc_MAC(),SM4_Block_Decrypt(),bytes128_to_ecn2()
 Called By: SM9_SelfCheck()
 Input:
 C //cipher C1||C3||C2
 C_len //the byte length of C
 deB //private key of user B
 IDB //identification of userB
 EncID //encryption identification,0:stream cipher 1:block cipher
 k1_len //the byte length of K1 in block cipher algorithm
 k2_len //the byte length of K2 in MAC algorithm
 Output:
 M //message
 Mlen: //the length of message
 Return:
 0: success
 1: asking for memory error
 2: element is out of order q
 3: R-ate calculation error
 4: test if C1 is on G1
 A: K1 equals 0
 B: compare error of C3
 Others:
****************************************************************/
int SM9_Decrypt(unsigned char C[], unsigned char B[], int C_len, unsigned char deB[], unsigned char* IDB, int EncID,
	int k1_len, int k2_len, int* B_len, unsigned char M[], int* Mlen)
{
	big x, y;
	epoint* C1;
	zzn12 w;
	ecn2 dEB;
	int mlen, klen, Zlen, i, number = 0;
	unsigned char* Z = NULL, * K = NULL, * K1 = NULL, u[SM3_len / 8];
	x = mirvar(0); y = mirvar(0);
	dEB.x.a = mirvar(0); dEB.x.b = mirvar(0); dEB.y.a = mirvar(0); dEB.y.b = mirvar(0);
	dEB.z.a = mirvar(0); dEB.z.b = mirvar(0); dEB.marker = MR_EPOINT_INFINITY;
	C1 = epoint_init(); zzn12_init(&w);
	bytes_to_big(BNLEN, C, x); bytes_to_big(BNLEN, C + BNLEN, y);
	bytes128_to_ecn2(deB, &dEB);//在公式中 deB实际上为skid
	//Step1:get C1,and test if C1 is on G1
	printf("\n*******************C1=r(H1(ID||hid,N)+alpha)\cdot P1*****************\n");
	cotnum(x, stdout); cotnum(y, stdout);
	epoint_set(x, y, 1, C1);
	if (Test_Point(C1)) return SM9_C1_NOT_VALID_G1;
	printf("\n*******************deB*****************\n");
	ecn2_Bytes128_Print(dEB);
	//Step2:w = e(C1, deB) w=e(skid,C1)
	if (!ecap(dEB, C1, para_t, X, &w)) return SM9_MY_ECAP_12A_ERR;
	//test if a ZZn12 element is of order q
	if (!member(w, para_t, X)) return SM9_MEMBER_ERR;
	printf("\n*********************** w = e(skid,C1):****************************\n");
	zzn12_ElementPrint(w);

	//Get C2
	ecn2 B2;
	B2.x.a = mirvar(0); B2.x.b = mirvar(0); B2.y.a = mirvar(0); B2.y.b = mirvar(0);
	B2.z.a = mirvar(0); B2.z.b = mirvar(0); B2.marker = MR_EPOINT_INFINITY;
	
	bytes_to_big(BNLEN, B + BNLEN * 2, B2.x.a);
	bytes_to_big(BNLEN, B + BNLEN * 3, B2.x.b);
	bytes_to_big(BNLEN, B + BNLEN * 4, B2.y.a);
	bytes_to_big(BNLEN, B + BNLEN * 5, B2.y.b);
	mlen = B_len - BNLEN * 6 - SM3_len / 8;
	//Compute K'=(C1||C2||w'||ID,klen)
	int B3_len;
	mlen = *B_len - BNLEN * 6 - SM3_len / 8;
	B3_len = mlen;
	*B_len = BNLEN * 6 + SM3_len / 8 + B3_len;
	klen = k1_len + k2_len;
	Zlen = strlen(IDB) + BNLEN * 18;//the size of IDB and other component space 
	Z = (char*)malloc(sizeof(char) * (Zlen + 1));
	K = (char*)malloc(sizeof(char) * (klen + 1));//compute the size of klen and one another space
	if (Z == NULL || K == NULL) return SM9_ASK_MEMORY_ERR;
	LinkCharZzn12(B, BNLEN * 6, w, Z, Zlen - strlen(IDB));//link the parameters 直接复制B的前BNLEN*6字节长度到z上
	memcpy(Z + BNLEN * 18, IDB, strlen(IDB));//copy IDB to Z+.. and the length of IDB computed by str(IDB)
	SM3_KDF(Z, Zlen, klen, K);//整合到K上,KDF
	printf("\n*****************K=KDF(C1||C2||w||ID,klen):***********************\n");
	for (i = 0; i < klen; i++) printf("%02x", K[i]);

	//Step3-1:m=C3异或K1  and test if K1==0?

	//Calculate plaintext M
	
	for (i = 0; i < mlen; i++)
	{
		if (K[i] == 0) number += 1;
		M[i] = B[i + BNLEN * 6] ^ K[i];
	}
	if (number == mlen) return SM9_ERR_K1_ZERO;
	*Mlen = mlen;
	//calculate u=MAC(K2,C3) 
	SM9_Enc_MAC(K + k1_len, k2_len, &B[BNLEN * 6], mlen, u);//把B[BNLEN * 6]中B3的数据提取出来再进入MAC
	printf("\n****************************** M:******************************\n");
	for (i = 0; i < mlen; i++) printf("%02x", M[i]);
	free(K); 
	free(Z);

	return 0;
}

/****************************************************************
 Function: SM9_Decrypt2  经过重加密的解密算法
 Description: SM9 Decryption algorithm*/
int SM9_Decrypt2(unsigned char hid[], unsigned char CT[], int * C_len, unsigned char deB[], unsigned char* IDB, int EncID,
	int k1_len, int k2_len, int *B_len, unsigned char M[], big ke, int* Mlen, int n, unsigned char S[], int S_single[], int* CT_len)
{

	//Step1:calculate T
	zzn12 T1, T2, T;
	zzn12_init(&T1);
	zzn12_init(&T2);
	zzn12_init(&T);

	//Comput delta，其中假设签名者序号为i
	int Zlen, buf;
	unsigned char* Z = NULL;
	unsigned char ID[1000];
	big mult_h, mult_add, h1, alphar, delta, mult_addr;
	h1 = mirvar(0);
	mult_h = mirvar(1);
	mult_add = mirvar(0);
	mult_addr = mirvar(0);
	alphar = mirvar(0);
	delta = mirvar(0);

	int tmp1 = 0, tmpa = 0, j;
	printf("\n");
	for (int i = 1; i < S_single[i]; i++) {//要注意，这里设置的签名者序号为i，因此计算的时候从S[1]开始
		Zlen = S_single[i] + 1;
		tmp1 = S_single[i];
		tmpa += S_single[i-1];
		for (j = 0; j < tmp1; j++) {
			ID[j] = S[j + tmpa];
		}
		for (j = 0; j < tmp1; j++) {
			printf("%c", ID[j]);
		}
		printf("\n");
		
		Z = (char*)malloc(sizeof(char) * (Zlen + 1));
		if (Z == NULL) return SM9_ASK_MEMORY_ERR;
		memcpy(Z, ID, tmp1);
		memcpy(Z + tmp1, hid, 1);
		SM9_H1(Z, Zlen, N, h1);
		multiply(h1, mult_h, mult_h);
	}
	
	add(mult_h, ke, mult_add);
	copy(ke, alphar);
	copy(mult_add, mult_addr);
	xgcd(mult_addr, N, mult_addr, mult_addr, mult_addr);
	xgcd(alphar, N, alphar, alphar, alphar);
	multiply(alphar, mult_add, delta);
	subtract(delta, mult_h, delta);

	//Compute e(delta·P1,C1p-1)
	//Get C1p
	ecn2 C1p;
	C1p.x.a = mirvar(0); C1p.x.b = mirvar(0);
	C1p.y.a = mirvar(0); C1p.y.b = mirvar(0);
	C1p.z.a = mirvar(0); C1p.z.b = mirvar(0);
	C1p.marker = MR_EPOINT_INFINITY;
	big a, b;
	a = mirvar(0);
	b = mirvar(0);
	zzn2 x, y;
	x.a = mirvar(0); x.b = mirvar(0);
	y.a = mirvar(0); y.b = mirvar(0);

	bytes_to_big(BNLEN, CT, b);
	bytes_to_big(BNLEN, CT + BNLEN * 1, a);
	copy(a, x.a);
	copy(b, x.b);
	bytes_to_big(BNLEN, CT + BNLEN * 2, b);
	bytes_to_big(BNLEN, CT + BNLEN * 3, a);
	copy(a, y.a);
	copy(b, y.b);
	zzn2_copy(&x, &C1p.x);
	zzn2_copy(&y, &C1p.y);
	
	
	//delta·P1
	epoint* Part1;
	Part1=epoint_init();
	ecurve_mult(delta, P1, Part1);
	epoint* Fp;//far point 
	Fp = epoint_init();
	ecurve_sub(Part1, Fp);//根据双线性对的性质，左右两边求逆是一样的效果,因此对于epoint类型求逆

	//ecap T1
	ecap(C1p, Fp, para_t, X, &T1);
	if (!ecap(C1p, Fp, para_t, X, &T1)) return SM9_MY_ECAP_12A_ERR;

	//get C6p
	epoint* C6p;
	C6p = epoint_init();
	bytes_to_big(BNLEN, CT + BNLEN * 34, a);
	bytes_to_big(BNLEN, CT + BNLEN * 35, a);
	epoint_set(a, b, 0, C6p);
	
	//get skid
	ecn2 dEB;
	dEB.x.a = mirvar(0); dEB.x.b = mirvar(0); dEB.y.a = mirvar(0); dEB.y.b = mirvar(0);
	dEB.z.a = mirvar(0); dEB.z.b = mirvar(0); dEB.marker = MR_EPOINT_INFINITY;
	bytes128_to_ecn2(deB, &dEB);

	//ecap T2
	if (!ecap(dEB, C6p, para_t, X, &T2)) return SM9_MY_ECAP_12A_ERR;

	//compute T
	zzn12 sigma, C5p;
	zzn12_init(&sigma);
	zzn12_init(&C5p);
	zzn12_mul(T1, T2, &T);
	zzn12_pow(T, mult_addr);

	//get C5p
	bytes_to_big(BNLEN, CT + BNLEN * 22, C5p.a.a.a);
	bytes_to_big(BNLEN, CT + BNLEN * 23, C5p.a.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 24, C5p.a.b.a);
	bytes_to_big(BNLEN, CT + BNLEN * 25, C5p.a.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 26, C5p.b.a.a);
	bytes_to_big(BNLEN, CT + BNLEN * 27, C5p.b.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 28, C5p.b.b.a);
	bytes_to_big(BNLEN, CT + BNLEN * 29, C5p.b.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 30, C5p.c.a.a);
	bytes_to_big(BNLEN, CT + BNLEN * 31, C5p.c.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 32, C5p.c.b.a);
	bytes_to_big(BNLEN, CT + BNLEN * 33, C5p.c.a.b);

	//compute sigma
	zzn12_div(C5p, T, &sigma);

	//compute the next euqation t·H1(IDi,||hid,N)·P1=C4p/H2(sigma)
	//t·H1(IDi,||hid,N)·P1
	//get C4p
	epoint* h2s, * re, * C4p;
	/*big s, t;
	s = mirvar(0);
	t = mirvar(0);*/
	h2s = epoint_init();
	re = epoint_init();
	C4p = epoint_init();
	bytes_to_big(BNLEN, CT + BNLEN * 20, a);
	bytes_to_big(BNLEN, CT + BNLEN * 21, b);
	epoint_set(a, b, 0, C4p);
	epoint2_copy(C4p, re);

	//the right of euqation
	h2s = GT_to_G1(sigma);
	ecurve_sub(h2s, re);//re=C4p-h2

	//compute w'
	//ecap(C2p,re)
	ecn2 C2p;
	C2p.x.a = mirvar(0); C2p.x.b = mirvar(0);
	C2p.y.a = mirvar(0); C2p.y.b = mirvar(0);
	C2p.z.a = mirvar(0); C2p.z.b = mirvar(0);
	C2p.marker = MR_EPOINT_INFINITY;
	bytes_to_big(BNLEN, CT + BNLEN * 4, b);
	bytes_to_big(BNLEN, CT + BNLEN * 5, a);
	copy(a, x.a);
	copy(b, x.b);
	bytes_to_big(BNLEN, CT + BNLEN * 6, b);
	bytes_to_big(BNLEN, CT + BNLEN * 7, a);
	copy(a, y.a);
	copy(b, y.b);
	zzn2_copy(&x, &C2p.x);
	zzn2_copy(&y, &C2p.y);

	//wpr
	zzn12 wpr;
	zzn12_init(&wpr);
	ecap(C2p, re, para_t, X, &wpr);
	//wp
	zzn12 wp, C3p;
	zzn12_init(&wp);
	zzn12_init(&C3p);
	bytes_to_big(BNLEN, CT + BNLEN * 8, C3p.a.a.a);
	bytes_to_big(BNLEN, CT + BNLEN * 9, C3p.a.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 10, C3p.a.b.a);
	bytes_to_big(BNLEN, CT + BNLEN * 11, C3p.a.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 12, C3p.b.a.a);
	bytes_to_big(BNLEN, CT + BNLEN * 13, C3p.b.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 14, C3p.b.b.a);
	bytes_to_big(BNLEN, CT + BNLEN * 15, C3p.b.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 16, C3p.c.a.a);
	bytes_to_big(BNLEN, CT + BNLEN * 17, C3p.c.a.b);
	bytes_to_big(BNLEN, CT + BNLEN * 18, C3p.c.b.a);
	bytes_to_big(BNLEN, CT + BNLEN * 19, C3p.c.a.b);

	zzn12_div(C5p, wpr, &wp);
	printf("\n********************************wp=**********************************\n");
	zzn12_ElementPrint(wp);

	//compute k
	//get C7p C2p
	epoint* C7p;
	C7p = epoint_init();
	bytes_to_big(BNLEN, CT + BNLEN * 36, a);
	bytes_to_big(BNLEN, CT + BNLEN * 37, b);
	epoint_set(a, b, 0, C7p);

	int klen,mlen;
	unsigned char* K = NULL, * C2 = NULL, CTP[1000];
	int B3_len;
	mlen = *CT_len - BNLEN * 38 - SM3_len / 8;
	B3_len = mlen;
	klen = k1_len + k2_len;
	Zlen = strlen(IDB) + BNLEN * 18;//the size of IDB and other component space 
	Z = (char*)malloc(sizeof(char) * (Zlen + 1));
	K = (char*)malloc(sizeof(char) * (klen + 1));//compute the size of klen and one another space
	if (Z == NULL || K == NULL) return SM9_ASK_MEMORY_ERR;
	memcpy(CTP, CT + BNLEN * 36, BNLEN * 2);

	/*bytes_to_big(BNLEN, CTP, a);
	bytes_to_big(BNLEN, CTP + BNLEN, b);
	cotnum(a, stdout); cotnum(b, stdout);*/

	memcpy(CTP, CT + BNLEN * 4, BNLEN * 4);
	LinkCharZzn12(CTP, BNLEN * 6, wp, Z, Zlen - strlen(IDB));//link the parameters
	memcpy(Z + BNLEN * 18, IDB, strlen(IDB));//copy IDB to Z+.. and the length of IDB computed by str(IDB)
	SM3_KDF(Z, Zlen, klen, K);//整合到K上,KDF
	printf("\n*****************K=KDF(C7||C2||w||ID,klen):***********************\n");
	for (int i = 0; i < klen; i++) printf("%02x", K[i]);

	//compute m
	int number = 0;
	for (int i = 0; i < mlen; i++) {
		if (K[i] == 0)number += 1;
		M[i] = CT[i + BNLEN * 38] ^ K[i];
	}
	if (number == mlen) return SM9_ERR_K1_ZERO;
	//compute u
	unsigned char u[SM3_len / 8];
	*Mlen = mlen;
	SM9_Enc_MAC(K + k1_len, k2_len, &CT[BNLEN * 38], mlen, u);
	printf("\n***********************M:****************************\n");
	for (int i = 0; i < mlen; i++) printf("%02x", M[i]);
	free(K); free(Z);

	return 0;
}
/****************************************************************
 Function: SM9_SelfCheck
 Description: SM9 self check
 Calls: MIRACL functions,SM9_Init(),SM9_GenerateEncryptKey(),
 SM9_Encrypt,SM9_Decrypt
 Called By:
 Input:
 Output:
 Return: 0: self-check success
 1: asking for memory error
 2: element is out of order q
 3: R-ate calculation error
 4: test if C1 is on G1
 5: base point P1 error
 6: base point P2 error
 7: Encryption public key generated error
 8: Encryption private key generated error
 9: encryption error
 A: K1 equals 0
 B: compare error of C3
 C: decryption error
 Others:
****************************************************************/
int SM9_SelfCheck()
{
	printf("\n*********************** Start***************************\n");
	//the master private key
	unsigned char KE[32] =
	{ 0x00,0x01,0xED,0xEE,0x37,0x78,0xF4,0x41,0xF8,0xDE,0xA3,0xD9,0xFA,0x0A,0xCC,0x4E,
	0x07,0xEE,0x36,0xC9,0x3F,0x9A,0x08,0x61,0x8A,0xF4,0xAD,0x85,0xCE,0xDE,0x1C,0x22 };
	unsigned char
		rand[32] = { 0x00,0x00,0xAA,0xC0,0x54,0x17,0x79,0xC8,0xFC,0x45,0xE3,0xE2,0xCB,0x25,0xC1,0x2B,
		0x5D,0x25,0x76,0xB2,0x12,0x9A,0xE8,0xBB,0x5E,0xE2,0xCB,0xE5,0xEC,0x9E,0x78,0x5C };
	unsigned char 
		rand2[32] = { 0xc1,0x41,0xc1,0x54,0x17,0x12,0x12,0x4f,0xb8,0xdf,0xb9,0x9d,0xe8,0xaa,0x29,0x42,
		0x90,0x93,0x20,0x5d,0xc7,0x6f,0x9d,0xcc,0xf4,0x24,0x44,0x25,0xa5,0x8a,0xba,0x73 };
	//standard datas
	unsigned char std_Ppub[64] =
	{ 0x78,0x7E,0xD7,0xB8,0xA5,0x1F,0x3A,0xB8,0x4E,0x0A,0x66,0x00,0x3F,0x32,0xDA,0x5C,
	 0x72,0x0B,0x17,0xEC,0xA7,0x13,0x7D,0x39,0xAB,0xC6,0x6E,0x3C,0x80,0xA8,0x92,0xFF,
	 0x76,0x9D,0xE6,0x17,0x91,0xE5,0xAD,0xC4,0xB9,0xFF,0x85,0xA3,0x13,0x54,0x90,0x0B,
	 0x20,0x28,0x71,0x27,0x9A,0x8C,0x49,0xDC,0x3F,0x22,0x0F,0x64,0x4C,0x57,0xA7,0xB1 };
	unsigned char std_deB[128] =
	{ 0x94,0x73,0x6A,0xCD,0x2C,0x8C,0x87,0x96,0xCC,0x47,0x85,0xE9,0x38,0x30,0x1A,0x13,
	 0x9A,0x05,0x9D,0x35,0x37,0xB6,0x41,0x41,0x40,0xB2,0xD3,0x1E,0xEC,0xF4,0x16,0x83,
	 0x11,0x5B,0xAE,0x85,0xF5,0xD8,0xBC,0x6C,0x3D,0xBD,0x9E,0x53,0x42,0x97,0x9A,0xCC,
	 0xCF,0x3C,0x2F,0x4F,0x28,0x42,0x0B,0x1C,0xB4,0xF8,0xC0,0xB5,0x9A,0x19,0xB1,0x58,
	 0x7A,0xA5,0xE4,0x75,0x70,0xDA,0x76,0x00,0xCD,0x76,0x0A,0x0C,0xF7,0xBE,0xAF,0x71,
	 0xC4,0x47,0xF3,0x84,0x47,0x53,0xFE,0x74,0xFA,0x7B,0xA9,0x2C,0xA7,0xD3,0xB5,0x5F,
	 0x27,0x53,0x8A,0x62,0xE7,0xF7,0xBF,0xB5,0x1D,0xCE,0x08,0x70,0x47,0x96,0xD9,0x4C,
	 0x9D,0x56,0x73,0x4F,0x11,0x9E,0xA4,0x47,0x32,0xB5,0x0E,0x31,0xCD,0xEB,0x75,0xC1 };
	unsigned char std_C_stream[116] =
	{ 0x24,0x45,0x47,0x11,0x64,0x49,0x06,0x18,0xE1,0xEE,0x20,0x52,0x8F,0xF1,0xD5,0x45,
	 0xB0,0xF1,0x4C,0x8B,0xCA,0xA4,0x45,0x44,0xF0,0x3D,0xAB,0x5D,0xAC,0x07,0xD8,0xFF,
	 0x42,0xFF,0xCA,0x97,0xD5,0x7C,0xDD,0xC0,0x5E,0xA4,0x05,0xF2,0xE5,0x86,0xFE,0xB3,
	 0xA6,0x93,0x07,0x15,0x53,0x2B,0x80,0x00,0x75,0x9F,0x13,0x05,0x9E,0xD5,0x9A,0xC0,
	 0xBA,0x67,0x23,0x87,0xBC,0xD6,0xDE,0x50,0x16,0xA1,0x58,0xA5,0x2B,0xB2,0xE7,0xFC,
	 0x42,0x91,0x97,0xBC,0xAB,0x70,0xB2,0x5A,0xFE,0xE3,0x7A,0x2B,0x9D,0xB9,0xF3,0x67,
	 0x1B,0x5F,0x5B,0x0E,0x95,0x14,0x89,0x68,0x2F,0x3E,0x64,0xE1,0x37,0x8C,0xDD,0x5D,
	 0xA9,0x51,0x3B,0x1C };
	unsigned char std_C_cipher[244] =//128+116=244
	{ 0x24,0x45,0x47,0x11,0x64,0x49,0x06,0x18,0xE1,0xEE,0x20,0x52,0x8F,0xF1,0xD5,0x45,
	 0xB0,0xF1,0x4C,0x8B,0xCA,0xA4,0x45,0x44,0xF0,0x3D,0xAB,0x5D,0xAC,0x07,0xD8,0xFF,
	 0x42,0xFF,0xCA,0x97,0xD5,0x7C,0xDD,0xC0,0x5E,0xA4,0x05,0xF2,0xE5,0x86,0xFE,0xB3,
	 0xA6,0x93,0x07,0x15,0x53,0x2B,0x80,0x00,0x75,0x9F,0x13,0x05,0x9E,0xD5,0x9A,0xC0,
	 0xFD,0x3C,0x98,0xDD,0x92,0xC4,0x4C,0x68,0x33,0x26,0x75,0xA3,0x70,0xCC,0xEE,0xDE,
	 0x31,0xE0,0xC5,0xCD,0x20,0x9C,0x25,0x76,0x01,0x14,0x9D,0x12,0xB3,0x94,0xA2,0xBE,
	 0xE0,0x5B,0x6F,0xAC,0x6F,0x11,0xB9,0x65,0x26,0x8C,0x99,0x4F,0x00,0xDB,0xA7,0xA8,
	 0xBB,0x00,0xFD,0x60,0x58,0x35,0x46,0xCB,0xDF,0x46,0x49,0x25,0x08,0x63,0xF1,0x0A,0x24,0x45,0x47,0x11,0x64,0x49,0x06,0x18,0xE1,0xEE,0x20,0x52,0x8F,0xF1,0xD5,0x45,
	 0xB0,0xF1,0x4C,0x8B,0xCA,0xA4,0x45,0x44,0xF0,0x3D,0xAB,0x5D,0xAC,0x07,0xD8,0xFF,
	 0x42,0xFF,0xCA,0x97,0xD5,0x7C,0xDD,0xC0,0x5E,0xA4,0x05,0xF2,0xE5,0x86,0xFE,0xB3,
	 0xA6,0x93,0x07,0x15,0x53,0x2B,0x80,0x00,0x75,0x9F,0x13,0x05,0x9E,0xD5,0x9A,0xC0,
	 0xBA,0x67,0x23,0x87,0xBC,0xD6,0xDE,0x50,0x16,0xA1,0x58,0xA5,0x2B,0xB2,0xE7,0xFC,
	 0x42,0x91,0x97,0xBC,0xAB,0x70,0xB2,0x5A,0xFE,0xE3,0x7A,0x2B,0x9D,0xB9,0xF3,0x67,
	 0x1B,0x5F,0x5B,0x0E,0x95,0x14,0x89,0x68,0x2F,0x3E,0x64,0xE1,0x37,0x8C,0xDD,0x5D,
	 0xA9,0x51,0x3B,0x1C };
	unsigned char* std_message = "Chinese IBE standard";
	unsigned char hid[] = { 0x03 };
	unsigned char* IDB = "Bob";
	unsigned char Ppub[64], deB[128];
	unsigned char message[1000], C[1000], B[1000], CT[1000], rk[1000], rkp[1000], S[1000], R[1000];
	int ID_len, S_len = 0, R_len = 0, tmp, i, S_single[20], R_single[10];

	memcpy(S, "Bob", strlen("Bob"));
	tmp = strlen("Bob");
	S_len += tmp;
	ID_len = tmp;
	S_single[0] = tmp;
	memcpy(S + S_len , "Alice", strlen("Alice"));
	tmp = strlen("Alice");
	S_len += tmp;
	S_single[1] = tmp;
	memcpy(S + S_len, "CoCo", strlen("CoCo"));
	tmp = strlen("CoCo");
	S_len += tmp;
	S_single[2] = tmp;
	memcpy(S + S_len, "Danes", strlen("Danes"));
	tmp = strlen("Danes");
	S_len += tmp;
	S_single[3] = tmp;
	//for (i = 0; i < S_len; i++) printf("%02x", S[i]); 

	memcpy(R, "Alice", strlen("Alice"));
	tmp = strlen("Alice");
	R_len += tmp;
	R_single[0] = tmp;
	memcpy(R + R_len, "CoCo", strlen("CoCo"));
	tmp = strlen("CoCo");
	R_len += tmp;
	R_single[1] = tmp;

	int M_len, C_len, B_len, CT_len;//M_len the length of message //C_len the length of C
	int k1_len = 16, k2_len = 32, max_mem=5, k=4, l=2;//最大撤销数量为2
	int EncID = 0;//0,stream //1 block
	
	big ke;
	printf("\n***********************Stage2***************************\n");
	tmp = SM9_Init();
	printf("\n***********************Stage3***************************\n");
	if (tmp != 0) return tmp;
	ke = mirvar(0);
	bytes_to_big(32, KE, ke);



	/*printf("\n*********************** SM9 key Generation ***************************\n");
	tmp = SM9_GenerateEncryptKey(hid, IDB, strlen(IDB), ke, Ppub, deB);
	if (tmp != 0) return tmp;
	if (memcmp(Ppub, std_Ppub, 64) != 0)
		return SM9_GEPUB_ERR;
	if (memcmp(deB, std_deB, 128) != 0)
		return SM9_GEPRI_ERR;
	printf("\n*********************** SM9 encrypt algorithm **************************\n");
	tmp = SM9_Encrypt(hid, IDB, std_message, strlen(std_message), rand,EncID, k1_len, k2_len, Ppub, C, B, &C_len, &B_len, ke);
	if (tmp != 0) return tmp;
	printf("\n****************************** Cipher:************************************\n");
	for (i = 0; i < B_len; i++) printf("%02x", B[i]); 
	printf("\n********************** SM9 Decrypt algorithm **************************\n");
	tmp = SM9_Decrypt(std_C_cipher, B, 128, deB, IDB, 2, k1_len, k2_len, &B_len,message, &M_len);
	printf("\n**************************** Message:***********************************\n");
	for (i = 0; i < M_len; i++) printf("%02x", message[i]);
	if (tmp != 0) return tmp;
	if (memcmp(message, std_message, M_len) != 0)
		return SM9_DECRYPT_ERR;*/

	//如果需要撤销
	printf("\n*********************** SM9 key Generation ***************************\n");
	tmp = SM9_GenerateEncryptKey(hid, IDB, strlen(IDB), ke, Ppub, deB);
	if (tmp != 0) return tmp;
	if (memcmp(Ppub, std_Ppub, 64) != 0)
		return SM9_GEPUB_ERR;
	if (memcmp(deB, std_deB, 128) != 0)
		return SM9_GEPRI_ERR;
	printf("\n*********************** SM9 encrypt algorithm **************************\n");
	tmp = SM9_Encrypt(hid, IDB, std_message, strlen(std_message), rand, EncID, k1_len, k2_len, Ppub, C, B, &C_len, &B_len, ke);
	if (tmp != 0) return tmp;
	printf("\n****************************** Cipher:************************************\n");
	for (i = 0; i < B_len; i++) printf("%02x", B[i]); 
	printf("\n****************************** ReKeyGeneration:************************************\n");
	tmp = SM9_ReKeyGen(hid, IDB, std_message, strlen(std_message), rand, rand2, EncID, k1_len, k2_len, deB, C, B, rk, &C_len, ke,max_mem, k, S, S_single);
	if (tmp) return SM9_REKEYGEN_ERR;
	printf("\n****************************** Revoke:************************************\n");
	tmp = SM9_Revoke(hid, IDB, message, strlen(std_message), rand, EncID, k1_len, k2_len, C, B, rk, rkp, &C_len, ke, k, l, S, R, R_single);
	if (tmp) return SM9_REVOKE_ERR;
	printf("\n*********************** SM9 reencrypt algorithm **************************\n");
	tmp = SM9_ReEncrycrypt(hid, IDB, std_message, rk, CT, rkp, strlen(std_message), rand, EncID, k1_len, k2_len, deB, C, B, &C_len, &B_len, ke,k, &CT_len);
	if (tmp != 0) return SM9_REENCRYPT_ERR;
	printf("\n****************************** ReEncryptedCipher:************************************\n");
	for (i = 0; i < B_len; i++) printf("%02x", CT[i]);
	if (EncID == 0) tmp = memcmp(CT, std_C_stream, C_len); else tmp = memcmp(CT, std_C_cipher, C_len);//
	tmp = SM9_Decrypt2(hid,CT,&C_len, deB, IDB, EncID,k1_len, k2_len, &B_len,message,ke, &M_len, k, S, S_single, &CT_len);//CT_len??
	printf("\n**************************** Message:***********************************\n");
	for (i = 0; i < M_len; i++) printf("%02x", message[i]);
	if (tmp != 0) return tmp;




	return 0;
}