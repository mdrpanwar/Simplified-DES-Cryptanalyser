# tested for K2 over all KEYs
# Given a 10 bit key, it computes the round keys and the original key
# include <stdio.h>
# include <stdlib.h>
# include <math.h>
# include <limits.h>
# include <string.h>
# define COLUMN unsigned int
# define ROW unsigned int
# define ELEMENT unsigned int
# define INDEX unsigned int
# define BYTE unsigned char
# define UINT unsigned int
# define BYTESIZE CHAR_BIT
# define BLOCKSIZE BYTESIZE
# define KEYSIZE 10
# define SUBKEYSIZE 8
# define SPLITKEYSIZE 5
# UINT cbin2UINT(char*, UINT);
from BitVector import *
import numpy as np
import warnings
warnings.filterwarnings("ignore")


# /*===============================global variables==========================*/
# BYTE R1X=0
# BYTE R1Y=0
# BYTE C=0
# BYTE C2=0
# int r=0
def makeBV(val, size):  # int, int ---> BV
    return BitVector(intVal=val, size=size)


# S1==[0,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3]
S0 = [[1, 0, 2, 3], [3, 1, 0, 2], [2, 0, 3, 1], [1, 3, 2, 0]]
S1 = [[0, 3, 1, 2], [3, 2, 0, 1], [1, 0, 3, 2], [2, 1, 3, 0]]

PC_1 = [9, 7, 3, 8, 0, 2, 6, 5, 1, 4]
PC_2 = [3, 1, 7, 5, 0, 6, 4, 2]
P = [1, 0, 3, 2]
E = [3, 0, 1, 2, 1, 2, 3, 0]
# E = [0,2,1,3,0,1,2,3];
r = 0
KeyFreqWithin = [0] * 256
KeyFreqAcross = [0] * 256
# decimal values
DPS0 = np.zeros(shape=(16, 16), dtype=np.int)
DTS0 = np.zeros(shape=(16, 4), dtype=np.int)
DPS1 = np.zeros(shape=(16, 16), dtype=np.int)
DTS1 = np.zeros(shape=(16, 4), dtype=np.int)
# S0tup=[]
# S1tup=[]

# BitVectors
KEY = makeBV(0, 10)
K1 = makeBV(0, 8)
K2 = makeBV(0, 8)
C = makeBV(0, 8)
C2 = makeBV(0, 8)
R1XCHAR = makeBV(0, 8)
R1YCHAR = makeBV(0, 8)
R1Y = makeBV(0, 8)


# dex=0
# dey=0
# dex2=0
# dey2=0
# prob=0.0
# prob2=0.0

def out_S(B, S):  # BitVector, 2D List
    [i, j] = B.permute([0, 3, 1, 2]).divide_into_two()
    [i, j] = [int(i), int(j)]
    out_S = BitVector(intVal=S[i][j], size=2)
    return out_S


# Construct a difference pair table for the two S-Boxes of S-DES
def diffPair():
    global DPS0, DPS1, S0, S1
    x = 0
    dx = 0
    for x in range(16):
        for dx in range(16):
            DPS0[x][dx] = int(
                ((out_S(BitVector(intVal=x, size=4), S0)) ^ (out_S(BitVector(intVal=x ^ dx, size=4), S0))))
            DPS1[x][dx] = int(
                ((out_S(BitVector(intVal=x, size=4), S1)) ^ (out_S(BitVector(intVal=x ^ dx, size=4), S1))))


# The difference distribution table
def diffTab():
    global DPS0, DPS1, DTS0, DTS1
    dx = 0
    dy = 0
    for dx in range(16):
        for dy in range(4):
            DTS0[dx][dy] = (DPS0[:, dx] == dy).sum()
            DTS1[dx][dy] = (DPS1[:, dx] == dy).sum()


def printDiffPS(DS):
    print("r'$\Delta$Y given r'$\Delta$X")
    print("--------------------------------------------------")
    print("x 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15")
    print("--------------------------------------------------")
    print(DS)


def printDistTab(DT):
    print(DT)


# def SortDiffList():
#     global S0tup,S1tup
#     for i in range(16):
#         for j in range(4):
#             S0tup.append((i,j,DTS0[i][j]))
#             S1tup.append((i,j,DTS1[i][j]))
#
#     S0tup = sorted(S0tup, key=lambda x: x[2],reverse=True)
#     S1tup = sorted(S1tup, key=lambda x: x[2],reverse=True)

def PC1(bv):  # BitVector
    global PC_1
    p_bv = bv.permute(PC_1)
    return p_bv.divide_into_two()


def keySchedule(KEY):  # BitVector ---> [BV,BV]
    global PC_2
    [C0, D0] = PC1(KEY)
    [C1, D1] = [C0 << 1, D0 << 1]
    drop_first_2 = (C1 + D1)[2:]
    K1 = drop_first_2.permute(PC_2)
    [C2, D2] = [C1 << 2, D1 << 2]
    drop_first_2 = (C2 + D2)[2:]
    K2 = drop_first_2.permute(PC_2)
    return [K1, K2]


def apply_f(R, K):  # BV,BV ----> BV
    global E, S0, S1, P
    RE = R.permute(E)
    bv = RE ^ K
    [B1, B2] = bv.divide_into_two()

    out_S0 = out_S(B1, S0)
    out_S1 = out_S(B2, S1)
    return (out_S0 + out_S1).permute(P)


def round(L, R, key):  # BV, BV, BV -----> [BV,BV]
    Ln = L ^ apply_f(R, key)
    Rn = R
    return [Ln, Rn]


def swap(L, R):  # BV,BV --->[BV,BV]
    t = L
    L = R
    R = t
    return [L, R]


def crypt(inp):  # BV
    global R1Y, r, C, C2
    [L0, R0] = inp.divide_into_two()
    [L1, R1] = round(L0, R0, K1)
    [L1, R1] = swap(L1, R1)
    # print("L1,R1", L1, R1)
    [L2, R2] = round(L1, R1, K2)
    # print("L2,R2", L2, R2)
    R1Y = L1 + R1
    combine = L2 + R2
    if r == 0:
        C = combine
        r += 1
    else:
        C2 = combine
        r -= 1


def finalRound(inp, key):  # BV, BV -----> BV
    [L, R] = inp.divide_into_two()
    [Lf, Rf] = round(L, R, key)
    return Lf + Rf


def getCharacteristics(bv_dex, bv_dey, bv_dex2, bv_dey2):  # BV, BV, BV, BV
    global R1XCHAR, R1YCHAR, E

    for i in range(4):
        if (bv_dex[i] == 1):
            R1XCHAR[4 + E[i]] = 1
            R1YCHAR[E[i]] = 1

        if (bv_dex2[i] == 1):
            R1XCHAR[4 + E[4+i]] = 1
            R1YCHAR[E[4+i]] = 1

    for i in range(2):
        if (bv_dey[i] == 1):
            R1YCHAR[4+P[i]]=1

        if (bv_dey2[i] == 1):
            R1YCHAR[4+P[2+i]]=1

def resetAll():
    global r, KeyFreqWithin, C, C2, R1XCHAR, R1YCHAR, R1Y
    r = 0
    KeyFreqWithin = [0] * 256
    C = makeBV(0, 8)
    C2 = makeBV(0, 8)
    R1XCHAR = makeBV(0, 8)
    R1YCHAR = makeBV(0, 8)
    R1Y = makeBV(0, 8)

def printBin(text,val,size):
    if(str(type(val))=="<class 'int'>"):
        print(text,makeBV(val,size),"["+str(val)," in decimal]")

    else:
        assert (val.length()==size), "Cannot print a BitVector of size different than the one passed."
        print(text,val,"["+str(int(val))," in decimal]")


if __name__ == '__main__':
    print("========== Automated Differential Cryptanalyser ==========")
    # userKey=input("Enter the 10 bit key")
    userKey = '0000001001'
    KEY = BitVector(bitstring=userKey)

    # diffPair()
    #     # diffTab()
    #     # print("Difference Pairs for S0")
    #     # printDiffPS(DPS0)
    #     # print("Difference Distribution Table for S0")
    #     # printDistTab(DTS0)
    #     # print("Difference Pairs for S1")
    #     # printDiffPS(DPS1)
    #     # print("Difference Distribution Table for S1")
    #     # printDistTab(DTS1)
    #     # print()


    # SortDiffList()
    # print(S0tup)
    # print(S1tup)

    match=0
    for kk in range(1024):
        KEY=makeBV(kk,10)
        KeyFreqAcross=[0]*256
        [K1, K2] = keySchedule(KEY)
        dex = dey = dex2 = dey2 = 0

        for dex in range(16):
            for dey in range(4):
                for dex2 in range(16):
                    for dey2 in range(4):
                        bv_dex = makeBV(dex, 4)
                        bv_dey = makeBV(dey, 2)
                        bv_dex2 = makeBV(dex2, 4)
                        bv_dey2 = makeBV(dey2, 2)
                        resetAll()
                        count = 0
                        getCharacteristics(bv_dex, bv_dey, bv_dex2, bv_dey2)
                        for input in range(256):
                            crypt(makeBV(input, 8))
                            currR1Y = R1Y
                            crypt(makeBV(input, 8) ^ R1XCHAR)
                            if ((R1Y ^ currR1Y) == R1YCHAR):
                                count += 1
                                for k in range(256):
                                    if (finalRound(currR1Y, makeBV(k, 8)) == C and finalRound(R1Y, makeBV(k, 8)) == C2):
                                        KeyFreqWithin[k] += 1

                        if (count != 0):
                            m = max(KeyFreqWithin)
                            max_keys = [i for i, j in enumerate(KeyFreqWithin) if j == m]
                            for i in max_keys:
                                KeyFreqAcross[i] += 1
                            break
                    else:
                        continue
                    break
                else:
                    continue
                break
            else:
                continue
            break

        m = max(KeyFreqAcross)
        guessed_key = KeyFreqAcross.index(m)
        printBin("KEY:",kk,10)
        printBin("Expected key:",K2,8)
        printBin("Guessed key:",guessed_key,8)
        if(int(K2)==guessed_key):
            match+=1

        print()

    print("Total Matched",match)