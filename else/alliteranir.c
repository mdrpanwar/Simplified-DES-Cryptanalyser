/**
*========== Automated Differential Cryptanalyser ==========
*Designed for: S-DES
*Developer 1: Dr. K.S. Ooi (ksooi@mailexcite.com)
*Developer 2: Brain Chin Vito (v@chin.tc)
*University of Sheffield Centre, Taylor's College
*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include <string.h>
#define COLUMN unsigned int
#define ROW unsigned int
#define ELEMENT unsigned int
#define INDEX unsigned int
#define BYTE unsigned char
#define UINT unsigned int
#define BYTESIZE CHAR_BIT
#define BLOCKSIZE BYTESIZE
#define KEYSIZE 10
#define SUBKEYSIZE 8
#define SPLITKEYSIZE 5
UINT cbin2UINT(char*, UINT);
/*===============================global variables==========================*/
BYTE R1X=0;
BYTE R1Y=0;
BYTE C=0;
int ct =0;
BYTE C2=0;
int r=0;
BYTE S0[]={1,0,2,3,3,1,0,2,2,0,3,1,1,3,2,0};
//BYTE S1[]={0,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3};
BYTE S1[] = {0,3,1,2,3,2,0,1,1,0,3,2,2,1,3,0};

BYTE v1left,v2left,v1right,v2right;
//BYTE E[] = {0,2,1,3,0,1,2,3};
BYTE E[] = {3,0,1,2,1,2,3,0};

BYTE P4[] = {1,0,3,2};
ELEMENT DPS0[16][16];
ELEMENT DTS0[16][4];
ELEMENT DP2S0[16][16];
ELEMENT DT2S0[16][4];
BYTE R1XCHAR=0;
BYTE R1YCHAR=0;
int dex=0,dey=0,dex2=0,dey2=0;
double prob=0.0,prob2=0.0;
UINT key10 = 255;
/* ======================== general functions ================================= */
/**
* E.g. of usage:
* //printBin(" 23 is: ", 23, BYTESIZE);
* //printBin(" ",cbin2UINT("10110010",BYTESIZE), BYTESIZE);
* //printBin(" 217 is: ", 217, BYTESIZE);
* //printf("String 11011001 is %u\n", cbin2UINT("11011001",BYTESIZE));
*
* //printBin(" 729 is: ", 729, 10);
* //printf("String 1011011001 is %u\n", cbin2UINT("1011011001",KEYSIZE));
*
*/
void printBin(const char *str,unsigned int bInteger,unsigned int nSize){
	char s[BYTESIZE*sizeof(UINT)];
	UINT i;
	UINT n=bInteger;
	for(i=0; i<nSize; i++)
		*(s + i)='0'; *(s+i)='\0';
	i= nSize - 1;
	while(n > 0){
		s[i--]=(n % 2)? '1': '0';
		n = n/2;
	}
	printf("%s%s [%+3u in decimal]\n",str,s,bInteger);
}
/**
* E.g. of usage:
* //printf("String 11011001 is %u\n", cbin2UINT("11011001",BYTESIZE));
* //printf("String 1011011001 is %u\n", cbin2UINT("1011011001",KEYSIZE));
*/
UINT cbin2UINT(char *s, unsigned int nSize){
	int nLen = strlen(s);
	UINT uResult = 0;
	while (--nLen >= 0)
		if(s[nLen] == '1')
			uResult = 1 << (nSize - nLen - 1) | uResult;
		return uResult;
	}
/* ======================== Key Scheduling ================================= */
/**
*
* Only valid for max size 10
* Shift size is two, max
* //printBin(" ",cbin2UINT("10110010",BYTESIZE), BYTESIZE);
* //printBin(" ",leftShift(bin2UINT("10110010",BYTESIZE),2,BYTESIZE), BYTESIZE);
* //printBin(" ",leftShift(bin2UINT("10110010",BYTESIZE),1,BYTESIZE), BYTESIZE);
*
*/
UINT leftShift(UINT nKey, UINT nShift, UINT nSize){
	UINT n = nKey >> (nSize - nShift), i, nMask=0;
	nKey <<= nShift;
	for(i=0; i< nSize; i++)
		nMask |= 1 << i;
	return (nKey | n) & nMask;
}
/**
* Permutation box p10
* //printBin(" ",box_p10(cbin2UINT("1011011001",KEYSIZE)),KEYSIZE);
*/
UINT p10[] ={9,7,3,8,0,2,6,5,1,4};
UINT box_p10(UINT key10){
	UINT uResult=0, i=0;
	for(; i< KEYSIZE; i++)
		if (1 << (KEYSIZE - p10[i] - 1) & key10)
			uResult |= 1 << (KEYSIZE - i - 1);
		return uResult;
	}
/**
* Split Key
* printBin("",splitKey(cbin2UINT("1011011001",KEYSIZE), keyArray),5);
* where keyArray is an array of 2 '5 bit' keys
*/
void splitKey(UINT p10Key10, UINT uResult[]){
/**
* 31 == 0000011111
* 992 == 1111100000
*/
	UINT H_SPLIT5BIT_MASK = 31, L_SPLIT5BIT_MASK = 992;
	uResult[0] = (p10Key10 & L_SPLIT5BIT_MASK) >> SPLITKEYSIZE;
	uResult[1] = p10Key10 & H_SPLIT5BIT_MASK;
}
/**
* Permutation box p8
*/
UINT p8[] = {3,1,7,5,0,6,4,2};
UINT box_p8(UINT key5[]){
UINT uResult=0, uTemp, i=0;
/*
* 255 = 11111111
*/
UINT uMask = 255;
uTemp = key5[0] << SPLITKEYSIZE | key5[1];
uTemp &= uMask;
for(; i< SUBKEYSIZE; i++)
	if (1 << (SUBKEYSIZE - p8[i] - 1) & uTemp)
		uResult |= 1 << (KEYSIZE - i - 3);
	return uResult;
}
/**
* Key Schedule
*/
void keySchedule(UINT key10,UINT key8[]){
	UINT key5[2]={0,0}, keyTemp, i;
	keyTemp = box_p10(key10);
	splitKey(keyTemp, key5);
	for(i=0; i<2 ; i++){
		key5[0] = leftShift(key5[0], i+1, SPLITKEYSIZE);
		key5[1] = leftShift(key5[1], i+1, SPLITKEYSIZE);
		key8[i]= box_p8(key5);
	}
}
/* ======================== IP and IP_1 ================================= */
UINT IP[] = {7,6,4,0,2,5,1,3};
UINT IP_1[]= {3,6,4,7,2,5,1,0};
BYTE per(UINT P[], BYTE input){
	BYTE bRes = 00;
	int i = 8;
	while(--i >= 0)
		if( 01 << (BLOCKSIZE - P[BLOCKSIZE - i - 1] - 1) & input )
			bRes |= (01 << i);
		return bRes;
	}
/* ======================== Round =============================== */
void split824(BYTE bInput8, BYTE bLR[]){
	BYTE L_mask = 240, H_mask = 15;
/** left */
	bLR[0] = (bInput8 & L_mask) >> 4;
/** right */
	bLR[1] = bInput8 & H_mask;
}
/**
* f-function
*/
BYTE f(BYTE bRight, BYTE key){
BYTE bRes = 00, bTemp;
BYTE sLR4[]={0,0}, r, c;
int i = SUBKEYSIZE;
while(--i >= 0)
	if( 01 << (4 - E[SUBKEYSIZE - i - 1] - 1) & bRight )
		bRes |= (01 << i);
	bRes ^= key;
	split824(bRes,sLR4);
	if(r == 0){
		v1left = sLR4[0];
		v1right = sLR4[1];

	}
	if(r ==1){
		v2left = sLR4[0];
		v2right = sLR4[1];
	}
	c = (sLR4[0] & 6) >> 1;
	r = (sLR4[0] & 8) >> 2 | (sLR4[0] & 01);
	sLR4[0] = S0[4*r + c] << 2;
	c = (sLR4[1] & 6) >> 1;
	r = (sLR4[1] & 8) >> 2 | (sLR4[1] & 01);
	sLR4[1] = S1[4*r + c];
	bTemp = sLR4[0] | sLR4[1];
	bRes = 00;
// permute using P4
	i=4;
	if(sLR4[0] == 1 && sLR4[1] == 1){
		printf("\nHURRAYYY!!!");
	}
	
	while(--i >= 0)
		if( 01 << (4 - P4[4 - i - 1] - 1) & bTemp )
			bRes |= (01 << i);
		return bRes;
	}
/**
* Encrypt the given inputbits and returns the encryped input.
* Besides it stores the following data in global variables:
* RY1 : Round 1 output
* C: Ciphertext for first plaintext to be encrypted
* C2: Ciphertext for second plaintext to be encrypted
*/
int crypt(BYTE inputbits){
	UINT key8[2]={0,0};
	BYTE input8 = inputbits, exInput8, i;
/** left and Right */
	BYTE LR[] ={00,00};
	keySchedule(key10,key8);
	if(ct == 0){
		printBin("First key is: ", key8[0], 8);
		printBin("Second key is: ", key8[1], 8);
		ct++;
	}

	//printBin("Key 1 is :",key8[0], 8);
	//printBin("Key 2 is :",key8[1], 8);
	
// ===> Start of the round
	exInput8 = input8;
	R1X=exInput8;
	for(i=0; i< 2; i++){
/** =====> begin round */
		split824(exInput8,LR);
		input8 = (f(LR[1],(BYTE)key8[i])^LR[0]) << 4;
		input8 |= LR[1];
		exInput8 = ((input8 & 240) >> 4) | ( (input8 & 15) << 4 );
/** =====> end of round */
		if(i==0){
			R1Y=exInput8;
		}
	}
	if(r==0){
		C=input8;
		r++;
	}else{
		C2=input8;
		r--;
	}
	return exInput8;
}
/**
* The last round of the cipher. Takes in an inputbit an a key and encrypt it,
* with that key for one round.
*/
BYTE lastRound(BYTE inputbits,UINT key){
/** left and Right */
	BYTE LR[] ={00,00};
	BYTE input8 = inputbits;
	BYTE exInput8;
	exInput8 = input8;
	split824(exInput8,LR);
	input8 = (f(LR[1],(BYTE)key)^LR[0]) << 4;
	input8 |= LR[1];
	return input8;
}
/*==========================cryptanalytical functions=======================*/
void init(){
	INDEX i,j;
	for(i=0;i<16;i++)
		for(j=0;j<16;j++){
			DPS0[i][j]=0;
			DP2S0[i][j]=0;
		}
		for(i=0;i<16;i++)
			for(j=0;j<4;j++){
				DTS0[i][j]=0;
				DT2S0[i][j]=0;
			}
		}
/**
* Returns the output value of the stated S-Box given the input to the S-Box.
*/
ELEMENT SIO(COLUMN col,BYTE S[16]){
	ELEMENT value;
	BYTE r,c;
	c = (col & 6) >> 1;
	r = (col & 8) >> 2 | (col & 01);
	value = S[4*r + c];
	return value;
}
/**
*Construct a difference pair table for the two S-Boxes of S-DES
*
*/
void difPair(){
	COLUMN x=0;
	COLUMN dx=0;
	for(x=0;x<16;x++)
		for(dx=0;dx<16;dx++){
			DPS0[x][dx]=((SIO(x,S0))^(SIO(x^dx,S0)));
			DP2S0[x][dx]=((SIO(x,S1))^(SIO(x^dx,S1)));
		}
	}
/**
*Counts the number of dy in the column dx in DS0
*dy: The output difference
*dx: The input difference
*DS0: The difference pair table
*/
ELEMENT count(COLUMN dx,ROW dy,ELEMENT DS0[16][16]){
	INDEX i;
	int cnt=0;
	for(i=0;i<16;i++)
		if((DS0[i][dx])==dy)
			cnt++;
		return cnt;
	}
/**
* The difference distribution table
*/
void difTab(){
	COLUMN dx=0;
	ROW dy=0;
	for(dx=0;dx<16;dx++){
		for(dy=0;dy<4;dy++){
			DTS0[dx][dy]=count(dx,dy,DPS0);
			DT2S0[dx][dy]=count(dx,dy,DP2S0);
		}
	}
}
/**
* Print out the difference pair table on the screen.
*/
void printDPT(ELEMENT DS0[16][16]){
	ROW x=0;
	COLUMN dx=0;
	printf("-------------------------------------------------- \n");
	printf(" ");
	putchar((char)383);
	printf("Y given ");
	putchar((char)383);
	printf("X \n");
	printf("-------------------------------------------------- \n");
	printf("x 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 \n");
	printf("-------------------------------------------------- \n");
	for(x=0;x<16;x++){
		printf("%.2d",x);
		for(dx=0;dx<16;dx++){
			printf(" %d",DS0[x][dx]);
		}
		putchar('\n');
	}
}
/**
* Print out the difference distribution table on the screen.
*/
void printDT(ELEMENT DS0[16][4]){
	ROW x=0;
	COLUMN dx=0;
	printf("-------------------\n");
	printf(" ");
	putchar((char)383);
	printf("Y \n");
	putchar((char)383);
	printf("X 0 1 2 3 \n");
	printf("--------------------\n");
	for(x=0;x<16;x++){
		printf("%.2d",x);
		for(dx=0;dx<4;dx++){
			printf(" %.2d",DS0[x][dx]);
		}
		putchar('\n');
	}
}
/**
* Find the largest value in the given difference distribution table
* and store it's column and row in a global variable dex and dey.
*/
void findDC(int ident,ELEMENT DTS[16][4]){
	ELEMENT curV=0,curL=0;
	INDEX i,j;
	if(ident==0){
		for(i=0;i<16;i++){
			for(j=0;j<4;j++){
				curV=DTS[i][j];
				if((curV>curL)&(curV!=16)){
					curL=curV;
					dex=i;
					dey=j;
				}
			}
		}prob=((double)curL)/16;}else{
			for(i=0;i<16;i++){
				for(j=0;j<4;j++){
					curV=DTS[i][j];
					if((curV>curL)&(curV!=16)){
						curL=curV;
						dex2=i;
						dey2=j;
					}
				}
			} prob2=((double)curL)/16;
		}
	}
/**
*Print the expected subkey on the screen
*/
void printES(){
	UINT key8[2]={0,0};
	keySchedule(key10,key8);
	printBin("Expected subkey = ",(key8[1]),SUBKEYSIZE);
}
/**
* Given an array of key counts, with the index representing the key,
* this function prints the key with the largest count as the Guessed Subkey
* on the Screen.
*/
void printGS(int K[256]){
	ELEMENT curV=0,curL=0;
	int i,k;
	
	for(i=0;i<255;i++){
		curV=K[i];
		if(curV>curL){
			curL=curV;
			k=i;
		}
	}
	//printf("%d ", curL);
	printBin("Guessed Subkey = ",k,SUBKEYSIZE);
}
/**
*Extend the Differential Characteristic of the S-Boxes to the round with
*consideration to the expansion and permutation in f.
*/
void extendDC(){
	if((dex&8)==8){
		R1XCHAR=(R1XCHAR|1);
		R1YCHAR=(R1YCHAR|16);
	}
	if((dex&4)==4){
		R1XCHAR=(R1XCHAR|8);
		R1YCHAR=(R1YCHAR|128);
	}
	//st
	if((dex&2)==2){
		R1XCHAR=(R1XCHAR|4);
		R1YCHAR=(R1YCHAR|64);
	}
	//end
	if((dex&1)==1){
		R1XCHAR=(R1XCHAR|2);
		R1YCHAR=(R1YCHAR|32);
	}
	if((dex2&8)==8){
		R1XCHAR=(R1XCHAR|4);
		R1YCHAR=(R1YCHAR|64);
	}
	//st
	if((dex2&4)==4){
		R1XCHAR=(R1XCHAR|2);
		R1YCHAR=(R1YCHAR|32);
	}
	//end
	if((dex2&2)==2){
		R1XCHAR=(R1XCHAR|1);
		R1YCHAR=(R1YCHAR|16);
	}
	if((dex2&1)==1){
		R1XCHAR=(R1XCHAR|1);
		R1YCHAR=(R1YCHAR|16);
	}
	//st
	if((dey&2)==2)
		R1YCHAR=(R1YCHAR|4);
	//end
	if((dey&1)==1)
		R1YCHAR=(R1YCHAR|8);
	//st
	if((dey2&2)==2)
		R1YCHAR=(R1YCHAR|1);
	//end
	if((dey2&1)==1)
		R1YCHAR=(R1YCHAR|2);
}
int main(void){
	BYTE input=0;
	BYTE dx=16;
	BYTE curR1Y=0;
	BYTE i;
	BYTE k;
	BYTE candidate=0;
	BYTE lstest=0;
	int count=0;
	int PK2[256];
	char cont,useKey;
	char userKey[]="0101110011";
	// crypt(1);
	key10 = cbin2UINT(userKey,KEYSIZE);
	//crypt(20);
	printf("========== Automated Differential Cryptanalyser ==========\n");
	putchar('\n');
	printf(" Do you want to use the predetermined key (y/n) ?");
	scanf("%c",&useKey);
	if(useKey!='y'){
		printf(" Please specify key to use (10 BITS) ?");
		scanf("%s",&userKey);
		key10 = cbin2UINT(userKey,KEYSIZE);
	}
	UINT key8[2]={0,0};
	keySchedule(key10,key8);

	printBin("k1 ",key8[0],8);
	printBin("k2 ",key8[1],8);

	printf("Press enter to continue\n");
	scanf("%c",&cont);
	init();
	difPair();
	difTab();
	printf("Difference Pairs for S0\n");
	printDPT(DPS0);
	printf("Press enter to continue\n");
	scanf("%c",&cont);
	printf("Difference Distribution Table for S0\n");
	printDT(DTS0);
	printf("Press enter to continue\n");
	scanf("%c",&cont);
	printf("Difference Pairs for S1\n");
	printDPT(DP2S0);
	printf("Press enter to continue\n");
	scanf("%c",&cont);
	printf("Difference Distribution Table for S1\n");
	printDT(DT2S0);
	findDC(0,DTS0);
	printf("Press enter to continue\n");
	scanf("%c",&cont);
	printf("For S-Box 0\n ----------\n");
	printf("Best Difference Pair: dex = %i , dey = %i \n",dex,dey);
	printf("Probability = %f \n",prob);
	findDC(1,DT2S0);
	putchar('\n');
	printf("For S-Box 1\n ----------\n");
	printf("Best Difference Pair: dex2 = %i , dey2 = %i \n",dex2,dey2);
	printf("Probability = %f \n",prob2);
	putchar('\n');
	printf("Probability of Characteristic\n ----------------------\n");
	printf("Best Difference Pair: dex2 = %i , dey2 = %i \n",dex2,dey2);
	printf("Probability = %f \n",prob*prob2);
	putchar('\n');
	printf("\nExtended values %d %d %d %d \n", dex, dey, dex2, dey2);
	//dex = 4;
	//dex2 = 1;
	//dey = 3;
	//dey2 = 3;
	
	printf("R1Ychar is : %d", R1YCHAR);
	for(i=0;i<255;i++)
		PK2[i]=0;
	printf("Press enter to continue\n");
	scanf("%c",&cont);
	for(dex = 0;dex <15;dex++){
		for(dey = 0; dey <3;dey++){
			for(dex2 = 0;dex2<15;dex2++){
				for(dey2= 0;dey2<3;dey2++){
					extendDC();
					count =0;
					int s = 0;
					
					for(int i=0;i<255;i++){
						PK2[i] = 0;
					}
					for(input=0;input<255;input++){
						crypt(input);
						//printf("The value of ip is : %d and enc is : %d\n", input, C);
						curR1Y=R1Y;
						crypt((BYTE)(input^R1XCHAR));
						//printf("vlaues are %d %d THe input diff at SBOX 1 is :%d\n", v1left, v2left, v1left^v2left);
						//printf("vlaues are %d %d THe input diff at SBOX 2 is : %d\n", v1right, v2right,v1right ^v2right);
						//if((v1left ^ v2left) == dex){
						//	printf("ar round 1 is %d %d ,at round 2 is : %d %d xor left %d xor right %d\n", v1left, v1right, v2left ,v2right, v1left ^ v2left, v1right ^ v2right);
						//}
						//printf("Req diff: %d\n", R1Y^curR1Y);
						if((R1Y^curR1Y)==(R1YCHAR)){
							count++;
							for(k=0;k<255;k++){
								if((lastRound(curR1Y,k)==C)&(lastRound(R1Y,k)==C2))
									PK2[k]++;
							}
						}
						if(count > 0){
							// printf("Count is : %d ", count);
							printGS(PK2);
							
						}
					}
				}
			}
		}
	}
	// for(input=0;input<255;input++){
	// 	crypt(input);
	// 	//printf("The value of ip is : %d and enc is : %d\n", input, C);
	// 	curR1Y=R1Y;
	// 	crypt((BYTE)(input^R1XCHAR));
	// 	//printf("vlaues are %d %d THe input diff at SBOX 1 is :%d\n", v1left, v2left, v1left^v2left);
	// 	//printf("vlaues are %d %d THe input diff at SBOX 2 is : %d\n", v1right, v2right,v1right ^v2right);
	// 	if((v1left ^ v2left) == dex){
	// 		printf("ar round 1 is %d %d ,at round 2 is : %d %d xor left %d xor right %d\n", v1left, v1right, v2left ,v2right, v1left ^ v2left, v1right ^ v2right);
	// 	}
	// 	//printf("Req diff: %d\n", R1Y^curR1Y);
	// 	if((R1Y^curR1Y)==(R1YCHAR)){
	// 		count++;
	// 		for(k=0;k<255;k++){
	// 			if((lastRound(curR1Y,k)==C)&(lastRound(R1Y,k)==C2))
	// 				PK2[k]++;
	// 		}
	// 	}
	// }
	/*
	for(i=0;i<255;i++)
		printf("Key %d = %d \n",i,PK2[i]);
	printf("COUNT=%d\n",count);
	//exit(0);
	printES();
	printGS(PK2);
	putchar('(');
	putchar((char)383);
	printf("X)");
	printBin("Round 1 Input Characteristic = ",R1XCHAR,BLOCKSIZE);
	putchar('(');
	putchar((char)383);
	printf("Y)");
	printBin("Round 1 Output Characteristic = ",R1YCHAR,BLOCKSIZE);
	return EXIT_SUCCESS;
	*/
}