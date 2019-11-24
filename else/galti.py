# E = [0,1,0,0,2,3,3,2]
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

def encrypt_s_des(inp_bv,KEY):
  [K1,K2] = keySchedule(KEY)
  # print(K1,K2)
  [L0,R0] = IP1(inp_bv)
  print("left  ",L0,"right ",R0)
  print("............Round 1 start................")
  [L1,R1] = round(L0,R0,K1)
  print("............Round 1 over................")
  print("left  ", L1, "right ", R1)
  print("............Round 2 start................")
  [L2,R2] = round(L1,R1,K2)
  print("............Round 2 over................")
  print("left  ", L2, "right ", R2)
  combine = L2+R2
  print("before inverse of IP ",combine)
  print("after inverse of IP", combine.unpermute(IP_1))
  return combine.unpermute(IP_1)

def IP1(bv):
  p_bv=bv.permute(IP_1)
  print("after initial perm",p_bv)
  return p_bv.divide_into_two()

def round(L,R,key):
  Ln=R
  Rn=L^apply_f(R,key)
  return [Ln,Rn]


def apply_f(R,K):
  print(".................Applying f.............")
  RE = R.permute(E)
  print("after E perm", RE)
  bv = RE^K
  print("xor with subkey",bv)
  [B1,B2]=bv.divide_into_two()
  print("to S0 ", B1, "to S1 ", B2)
  out_S0 = out_S(B1,S0)
  out_S1 = out_S(B2,S1)
  print("out of S0 ",out_S0,"out of S1 ",out_S1)
  print("permute P ",(out_S0 + out_S1).permute(P))
  return (out_S0 + out_S1).permute(P)

def out_S(B,S):
  [i,j]=B.permute([0,3,1,2]).divide_into_two()
  [i,j]=[int(i),int(j)]
  out_S = BitVector(intVal=S[i][j],size=2)
  return out_S

def keySchedule(KEY):

  [C0,D0]=PC1(KEY)
  print("C0",C0,"D0",D0)
  [C1,D1]=[C0<<1,D0<<1]
  print("C1", C1, "D1", D1)
  drop_first_2 = (C1+D1)[2:]
  # print("drop the first two ",drop_first_2)
  K1=drop_first_2.permute(PC_2)
  # print("perm with PC_2.....")
  print("Subkey K1 ",int(K1))
  [C2,D2]=[C1<<2,D1<<2]
  print("C2", C2, "D2", D2)
  # print("perm with PC_2.....")
  drop_first_2 = (C2 + D2)[2:]
  # print("drop the first two ",drop_first_2)
  K2=drop_first_2.permute(PC_2)
  print("Subkey K2 ", int(K2))
  return [K1,K2]

def PC1(bv):
  p_bv=bv.permute(PC_1)
  # print("After PC_1 perm",p_bv)
  return p_bv.divide_into_two()


# to_enc=input("Enter the character to encrypt")
# KEY=input("Enter the KEY")
to_enc='10001101'
KEY='1011110001'
inp_bv=BitVector(bitstring=to_enc)
# print("plaintext",inp_bv)
KEY=BitVector(bitstring=KEY)
print("KEY ",KEY)
[K1, K2] = keySchedule(KEY)

print(KEY)
enc=encrypt_s_des(inp_bv,KEY)
print("encrypted",  enc)