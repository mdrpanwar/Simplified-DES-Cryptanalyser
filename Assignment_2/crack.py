#################
# crack.py      #
# Madhur Panwar #
# 2016B4A70933P #
#################
# Given a 10 bit key, it computes the 8 bit round keys and the original 10 bit key
from BitVector import *
import numpy as np
import warnings
warnings.filterwarnings("ignore")


# ===============================global variables==========================
def makeBV(val, size):  # int, int ---> BV
    return BitVector(intVal=val, size=size)

S0 = [[1, 0, 2, 3], [3, 1, 0, 2], [2, 0, 3, 1], [1, 3, 2, 0]]

# this S1 is given in the S-DES description given on page 13 in the paper
S1 = [[0, 3, 1, 2], [3, 2, 0, 1], [1, 0, 3, 2], [2, 1, 3, 0]]

# this S1 is used in the code given in paper on page 33
# S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]


PC_1 = [9, 7, 3, 8, 0, 2, 6, 5, 1, 4]
PC_2 = [3, 1, 7, 5, 0, 6, 4, 2]
P = [1, 0, 3, 2]
# this E is given in the S-DES description given on page 13 in the paper
E = [3, 0, 1, 2, 1, 2, 3, 0]
RS2 = [3, 4, 0, 1, 2]
LS2 = [2, 3, 4, 0, 1]
RS = [4, 0, 1, 2, 3]
LS = [1, 2, 3, 4, 0]
# this E is used in the code given in paper on page 33
# E = [0,2,1,3,0,1,2,3]

DiffList = []
r = 0
KeyFreqWithin = [0] * 256
KeyFreqAcross = [0] * 256

# Difference Pair Table and Difference Distribution Table
DPS0 = np.zeros(shape=(16, 16), dtype=np.int)
DTS0 = np.zeros(shape=(16, 4), dtype=np.int)
DPS1 = np.zeros(shape=(16, 16), dtype=np.int)
DTS1 = np.zeros(shape=(16, 4), dtype=np.int)

# BitVectors
KEY = makeBV(0, 10)
K1 = makeBV(0, 8)
K2 = makeBV(0, 8)

C = makeBV(0, 8)
C2 = makeBV(0, 8)

# Input and Output Differential Characteristics of Round 1
R1XCHAR = makeBV(0, 8)
R1YCHAR = makeBV(0, 8)

R1Y = makeBV(0, 8)


# Get the output of S-Box S given the input B
def out_S(B, S):  # BV, 2D List ---> BV
    [i, j] = B.permute([0, 3, 1, 2]).divide_into_two()
    [i, j] = [int(i), int(j)]
    out_S = BitVector(intVal=S[i][j], size=2)
    return out_S


# Construct a difference pair table for the two S-Boxes of S-DES
def diffPair():
    global DPS0, DPS1
    for x in range(16):
        for dx in range(16):
            DPS0[x][dx] = int(
                ((out_S(BitVector(intVal=x, size=4), S0)) ^ (out_S(BitVector(intVal=x ^ dx, size=4), S0))))
            DPS1[x][dx] = int(
                ((out_S(BitVector(intVal=x, size=4), S1)) ^ (out_S(BitVector(intVal=x ^ dx, size=4), S1))))


# Construct the difference distribution table
def diffTab():
    global DTS0, DTS1
    for dx in range(16):
        for dy in range(4):
            DTS0[dx][dy] = (DPS0[:, dx] == dy).sum()
            DTS1[dx][dy] = (DPS1[:, dx] == dy).sum()


# Print the Difference Pair Table DS
def printDiffPS(DS):
    print("----------------------------------------------------------------------------")
    print("Column Header represents the value of input difference delta X and the values")
    print("in the column are all possible output differences delta Y given that delta X.")
    print("----------------------------------------------------------------------------")
    print(DS)


# Print the Difference Distribution Table DT
def printDistTab(DT):
    print("----------------------------------------------------------------------------")
    print("Rows and Column Headers are the input and output differences respectively.")
    print("Value at index i,j in the table gives the number of times output difference")
    print("j occurs given the input difference i.")
    print("----------------------------------------------------------------------------")
    print(DT)


# Apply the permutation PC1 to bv and return after dividing the result into two equal parts
def PC1(bv):  # BV ---> [BV, BV]
    p_bv = bv.permute(PC_1)
    return p_bv.divide_into_two()


# Generate the 8 bit round keys K1 and K2 given the 10 bit KEY
def keySchedule(KEY):  # BV ---> [BV,BV]
    [C0, D0] = PC1(KEY)
    [C1, D1] = [C0.permute(LS), D0.permute(LS)]
    drop_first_2 = (C1 + D1)[2:]
    K1 = drop_first_2.permute(PC_2)
    [C2, D2] = [C1.permute(LS2), D1.permute(LS2)]
    drop_first_2 = (C2 + D2)[2:]
    K2 = drop_first_2.permute(PC_2)
    return [K1, K2]


# computes f(R,K) and returns it
def apply_f(R, K):  # BV,BV ----> BV
    RE = R.permute(E)
    bv = RE ^ K
    [B1, B2] = bv.divide_into_two()
    out_S0 = out_S(B1, S0)
    out_S1 = out_S(B2, S1)
    return (out_S0 + out_S1).permute(P)


# performs a single round of the cipher
def round(L, R, key):  # BV, BV, BV -----> [BV,BV]
    Ln = L ^ apply_f(R, key)
    Rn = R
    return [Ln, Rn]


# swaps the values of L and R and returns
def swap(L, R):  # BV,BV --->[BV,BV]
    t = L
    L = R
    R = t
    return [L, R]


# Given the input inp, performs the encryption, ignoring the initial permutation since it does not alter the differences
def crypt(inp):  # BV
    global R1Y, r, C, C2
    [L0, R0] = inp.divide_into_two()
    [L1, R1] = round(L0, R0, K1)
    [L1, R1] = swap(L1, R1)
    [L2, R2] = round(L1, R1, K2)
    R1Y = L1 + R1
    combine = L2 + R2
    if r == 0:
        C = combine
        r += 1
    else:
        C2 = combine
        r -= 1


# perform the last round of the cipher
def finalRound(inp, key):  # BV, BV -----> BV
    [L, R] = inp.divide_into_two()
    [Lf, Rf] = round(L, R, key)
    return Lf + Rf


# Given the inputs and outputs of the S-Boxes, computes the
# input and output differential characteristics for the first round
def getCharacteristics(bv_dex, bv_dey, bv_dex2, bv_dey2):  # BV, BV, BV, BV
    global R1XCHAR, R1YCHAR

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


# resets certain computation objects to zero
def resetAll():
    global r, KeyFreqWithin, C, C2, R1XCHAR, R1YCHAR, R1Y
    r = 0
    KeyFreqWithin = [0] * 256
    C = makeBV(0, 8)
    C2 = makeBV(0, 8)
    R1XCHAR = makeBV(0, 8)
    R1YCHAR = makeBV(0, 8)
    R1Y = makeBV(0, 8)


# A generic function to display 'text' followed by the 'size' length bitstring of integer represented by 'val'
def printBin(text,val,size): # str, BV or int, int
    if str(type(val))=="<class 'int'>":
        print(text,makeBV(val,size),"["+str(val)," in decimal]")

    else:
        assert (val.length()==size), "Cannot print a BitVector of size different than the one passed."
        print(text,val,"["+str(int(val))," in decimal]")


# generates round 1 key given C1D1
def generateR1key(C1D1): # BV ---> BV
    return (C1D1[2:]).permute(PC_2)


# returns the output of round 1 on input 'bv' and round 1 key 'k'.
def encryptR1(bv,k):# BV, BV ---> BV
    [L,R] = bv.divide_into_two()
    [L,R] = round(L, R, k)
    return L+R


# returns the frequency of matching outputs of round 1 using the round 1 actual key and the one generated using C1D1
def getC1D1Freq(C1D1): # BV ---> int
    f = 0
    key = generateR1key(C1D1)
    for inp in range(256):
        bv = makeBV(inp,8)
        if encryptR1(bv,K1) == encryptR1(bv,key):
            f += 1
    return f


# Find C1D1 (used to find the round 1 key and main key) given the round 2 guessed key
def getC1D1(gK2): # BV ---> BV
    freq={}
    C2D2 = gK2.unpermute(PC_2)
    C2D2.pad_from_left(2)
    [C2, D2] = C2D2.divide_into_two()
    D1 = D2.permute(RS2)

    # check for dropped bits being 00
    C1 = C2.permute(RS2)
    freq[int(C1+D1)] = getC1D1Freq(C1 + D1)

    # check for dropped bits being 01
    C2[1]=1
    C1 = C2.permute(RS2)
    freq[int(C1 + D1)] = getC1D1Freq(C1 + D1)

    # check for dropped bits being 11
    C2[0]=1
    C1 = C2.permute(RS2)
    freq[int(C1 + D1)] = getC1D1Freq(C1 + D1)

    # check for dropped bits being 10
    C2[1] = 0
    C1 = C2.permute(RS2)
    freq[int(C1 + D1)] = getC1D1Freq(C1 + D1)

    # returns the key corresponding to maximum value n dictionary freq
    return makeBV(max(freq, key=freq.get),10)


# Find the main KEY given C1D1
def getKEY(C1D1): # BV ---> BV
    [C1, D1] = C1D1.divide_into_two()
    [C1, D1] = [C1.permute(RS), D1.permute(RS)]
    [C0, D0] = [C1, D1]
    gKEY = (C0+D0).unpermute(PC_1)
    return gKEY


# makes the tuple to be put into DiffList
def makeTup(s0_i, s0_j, s1_i, s1_j):
    s0tup = (s0_i, s0_j, DTS0[s0_i][s0_j])
    s1tup = (s1_i, s1_j, DTS1[s1_i][s1_j])
    prod = s0tup[2] * s1tup[2]
    tup = (s0tup, s1tup, prod)
    return tup


# fills DiffList with index tuples and product of probability
def makeProdList():
    global DiffList
    for s0_i in range(16):
        for s0_j in range(4):
            for s1_i in range(16):
                for s1_j in range(4):
                    tup = makeTup(s0_i, s0_j, s1_i, s1_j)
                    DiffList.append(tup)


# Sorts DiffList based on decreasing order of probabilities
def SortDiffList():
    global DiffList
    makeProdList()
    DiffList = sorted(DiffList, key=lambda x: x[2], reverse=True)


# finds the round 2 key based on first pair of SBox input and output
# differences which give non-zero count of matching first round differentials
def useCountSearch():
    global K1, K2, KeyFreqWithin, KeyFreqAcross
    [K1, K2] = keySchedule(KEY)

    for dex in range(1, 16):
        for dey in range(4):
            for dex2 in range(1, 16):
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


# finds the key based on the decreasing order of SBox difference product probabilities
def useProbSearch():
    global K1, K2, KeyFreqWithin, KeyFreqAcross
    [K1, K2] = keySchedule(KEY)

    for x in DiffList:
        dex = x[0][0]
        dey = x[0][1]
        dex2 = x[1][0]
        dey2 = x[1][1]
        if (dex == 0 or dex2 == 0):
            continue
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

if __name__ == '__main__':
    print("========== Automated Differential Cryptanalyser ==========")
    print()

    # sort the list of product probabilities of input and output SBox differences
    SortDiffList()

    userKey = input("Enter the 10 bit key: ")
    KEY = BitVector(bitstring=userKey)
    assert (KEY.length() == 10), "KEY must be of exactly 10 bits."

    diffPair()
    diffTab()

    # =======Uncomment below to print Difference Pair Table and Difference Distribution Table========
    # print()
    # print("Difference Pairs for S0")
    # printDiffPS(DPS0)
    # print()
    # print("Difference Distribution Table for S0")
    # printDistTab(DTS0)
    # print()
    # print("Difference Pairs for S1")
    # printDiffPS(DPS1)
    # print()
    # print("Difference Distribution Table for S1")
    # printDistTab(DTS1)
    # print()
    # =========================================================================================================


    # useCountSearch()    # Method 1 for round 2 key search

    useProbSearch()   # Method 2 for round 2 key search

    print()

    m = max(KeyFreqAcross)
    guessed_key2 = KeyFreqAcross.index(m)
    printBin("Expected key for round 2:",K2,8)
    printBin("Guessed key for round 2: ",guessed_key2,8)
    print()
    C1D1 = getC1D1(makeBV(guessed_key2,8))
    guessed_key1 = (C1D1[2:]).permute(PC_2)
    printBin("Expected key for round 1:", K1, 8)
    printBin("Guessed key for round 1: ", guessed_key1, 8)
    print()
    guessed_KEY = getKEY(C1D1)
    printBin("Expected main KEY:", KEY, 10)
    printBin("Guessed main KEY: ", guessed_KEY, 10)
    print()
