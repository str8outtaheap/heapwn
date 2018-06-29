import angr
import sys

def main(argv):
  start_address = 0x4013F0
  find_address = 0x401531
  avoid_address = 0x40145A
  project = angr.Project('./sftp')
  state = project.factory.blank_state(addr=start_address)

  for _ in xrange(7):
    k = state.posix.files[0].read_from(1)
    state.solver.add(k >= 0x41)
    state.solver.add(k <= 0x7a)
    state.solver.add(k != 0x60)

  state.posix.files[0].seek(0)
  state.posix.files[0].length = 7
  simulation = project.factory.simgr(state)
  simulation.explore(find=find_address, avoid=avoid_address)

  if simulation.found:
    solution_state = simulation.found[0]
    print solution_state.posix.dumps(sys.stdin.fileno())
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
