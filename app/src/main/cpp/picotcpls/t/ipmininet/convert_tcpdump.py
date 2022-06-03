import argparse
import os

parser = argparse.ArgumentParser(description="Process a tcpdump -n trace and\
                                 convert it to the following format:\
                                 %H:%M:%S.%µS IP_SRC > IP_DEST LENGTH")
parser.add_argument("-t", type=str, help="Path to the _ascii_ trace file",
                    required=True)
parser.add_argument("-o", type=str, help="Output directorty, default .", default=".")
parser.add_argument("-oname", type=str, help="Output filename", required=True)

if __name__ == "__main__":

  args = parser.parse_args()
  outputf = open(os.path.join(args.o, args.oname), 'a')
  with open(args.t) as trace:
      packet_length = 0
      ip_line = True
      paths = {}
      for line in trace:
          if "ICMP" in line or "link-address" in line or "Ethernet" in line or \
          "flowlabel" in line or "tcpdump" in line or "length" not in line:
              continue

          if ip_line:
              timestr = line.split(" ")[0]
              if "IP" in timestr:
                  trace.readline()
                  continue
              if "IP6" in line:
                  packet_length = int(line.split("length:")[1].split(")")[0])
                  ip_src = line.split(">")[0].split()[-1]
                  ip_dest = line.split(">")[1].split()[0][:-1]
                  print("{0} {1} > {2} {3}".format(timestr, ip_src, ip_dest,
                                                   packet_length),
                        file=outputf)
              else:
                  packet_length = int(line.split("length")[1].split(")")[0])
                  ip_line=False
          else:
              if "IP6" in line:
                  packet_length = int(line.split("length:")[1].split(")")[0])
                  timestr = line.split(" ")[0]
                  ip_src = line.split(">")[0].split()[-1]
                  ip_dest = line.split(">")[1].split()[0].split(":")[0][:-1]
                  print("{0} {1} > {2} {3}".format(timestr, ip_src, ip_dest,
                                                   packet_length),
                        file=outputf)
              else:
                  ip_src = line.split()[0]
                  ip_dest = line.split()[2].split(":")[0]
                  print("{0} {1} > {2} {3}".format(timestr, ip_src, ip_dest,
                                                   packet_length),
                        file=outputf)
                  ip_line=True




