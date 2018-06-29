from z3 import *

def find_password(length):
  s = Solver()
  password = []
        
  for i in range(length):
    password.append(BitVec('c%d' % i, 8))
    s.add(Or(
          And(password[i] > 0x40, password[i] < 0x5b),
          And(password[i] > 0x60, password[i] < 0x7b)
    ))
    _hash = BitVecVal(0x5417, 16)
        
  for i in range(length):
    _hash = SignExt(8, password[i]) ^ _hash
    _hash = _hash * 2
    s.add(_hash == 0x8dfa)
        
  if s.check() == sat:
    m = s.model()
    result = ""
    for i in range(length):
      obj = password[i]
      c = m[obj].as_long()
      result += chr(c)
      print result

for i in range(1, 15+1):
  find_password(i)
