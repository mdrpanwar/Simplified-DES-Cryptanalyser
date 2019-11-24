#################
# Encrypt.py    #
# Madhur Panwar #
# 2016B4A70933P #
#################
from BitVector import  *
import warnings
warnings.filterwarnings("ignore")

IP_1=[7, 6, 4, 0, 2, 5, 1, 3]
PC_1=[9, 7, 3, 8, 0, 2, 6, 5, 1, 4]
PC_2=[3, 1, 7, 5, 0, 6, 4, 2]
P = [1,0,3,2]
E = [3, 0, 1, 2, 1, 2, 3, 0]
S0 = [[1,0,2,3],[3,1,0,2],[2,0,3,1],[1,3,2,0]]
S1 = [[0,3,1,2],[3,2,0,1],[1,0,3,2],[2,1,3,0]]
LS2 = [2, 3, 4, 0, 1]
LS = [1, 2, 3, 4, 0]

# change these filenames as desired
FILEPT = 'plaintext.txt' # plaintext file
FILECT = 'ciphertext.txt'# ciphertext file

BLOCKSIZE = 8


def encrypt_s_des(inp_bv,KEY):
  [K1,K2] = keySchedule(KEY)
  [L0,R0] = IP1(inp_bv)
  [L1,R1] = round(L0,R0,K1)
  [L1,R1]=swap(L1,R1)
  [L2,R2] = round(L1,R1,K2)
  combine = L2+R2
  return combine.unpermute(IP_1)

def swap(L,R):
  t=L
  L=R
  R=t
  return [L,R]


def IP1(bv):
  p_bv=bv.permute(IP_1)
  return p_bv.divide_into_two()

def round(L,R,key):
  Ln=L^apply_f(R,key)
  Rn=R
  return [Ln,Rn]


def apply_f(R,K):
  RE = R.permute(E)
  bv = RE^K
  [B1,B2]=bv.divide_into_two()
  out_S0 = out_S(B1,S0)
  out_S1 = out_S(B2,S1)
  return (out_S0 + out_S1).permute(P)

def out_S(B,S):
  [i,j]=B.permute([0,3,1,2]).divide_into_two()
  [i,j]=[int(i),int(j)]
  out_S = BitVector(intVal=S[i][j],size=2)
  return out_S

def keySchedule(KEY):
  [C0,D0]=PC1(KEY)
  [C1,D1]=[C0.permute(LS),D0.permute(LS)]
  drop_first_2 = (C1 + D1)[2:]
  K1=drop_first_2.permute(PC_2)
  [C2,D2]=[C1.permute(LS2),D1.permute(LS2)]
  drop_first_2 = (C2 + D2)[2:]
  K2=drop_first_2.permute(PC_2)
  return [K1,K2]

def PC1(bv):
  p_bv=bv.permute(PC_1)
  return p_bv.divide_into_two()


if __name__=='__main__':
  print()
  userKey = input("Enter the 10 bit key: ")
  KEY = BitVector(bitstring=userKey)
  assert (KEY.length() == 10), "KEY must be of exactly 10 bits."

  bv = BitVector(filename=FILEPT)
  msg_encrypted_bv = BitVector(size=0)

  while (bv.more_to_read):
    bv_read = bv.read_bits_from_file(BLOCKSIZE)
    if len(bv_read) < BLOCKSIZE:
      bv_read += BitVector(size=(BLOCKSIZE - len(bv_read)))
    bv_read = encrypt_s_des(bv_read,KEY)
    msg_encrypted_bv += bv_read


  outputhex = msg_encrypted_bv.get_hex_string_from_bitvector()

  FILEOUT = open(FILECT, 'w')
  FILEOUT.write(outputhex)
  FILEOUT.close()