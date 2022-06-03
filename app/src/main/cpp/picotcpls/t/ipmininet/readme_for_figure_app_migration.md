# Generating results for the application-level connection migration.

First, change your directory to the one in which this Readme file is.

Assuming ipmininet has been successfully [installed](https://ipmininet.readthedocs.io/en/latest/install.html) and picotcpls successfuly compiled (follow the main readme), the first step is to launch the network:

```bash
$ sudo python3 test_network_2paths.py  
```

This script configures a mininet experiment with a client, a server, some routers and 2 IP-level paths. 

Open a terminal for the client and server from mininet's command line interpreter:

```bash
xterm c s
```

If for some reasons you have issues with xterm, you may also directly
launch the server/client scripts on the mininet CLI. (e.g., `s
./run_test_server_multipath.sh &`)

You will need to capture a tcpdump trace during the experiment. Here's how you can do:  

open a client terminal

```bash
xterm c
```
then on the client's terminal, launch tcpdump right before launching the
experiment above:

```bash
tcpdump -n -i c-eth0 -v > my_exp_tcpls_migration.pcap
```

Then, on the server, do:

```bash
./run_test_server_multipath.sh
```

On client, do the following to launch the experiment:

```bash
./run_test_client_multipath.sh
```

This experiment will download a 60MiB file and perform two
application-level migrations during the download. The file
"tcpls_migration_goodput" should be generated and be available in the
current directory. If you do the experiment several times, be careful to
erase tcpls_migration_goodput or the next experiment's result would just
be appended to the file.


kill it when the experiment completed. You can either 'quit' ipmininet
from the CLI or ctrl-c the tcpdump process.

Important! Save the timing events you see on the console (or redirect stdout to
a file). Those are STREAM_ATTACH events, STREAM_CLOSE events, i.e., all events
that the script in the paper's repository /pretty_plotify/plot_aggregate.py
requires.


After the experiment, convert the .pcap using the python script convert_tcpdump.py: (use -oname tcpls_migration_pruned.log)

```
usage: convert_tcpdump.py [-h] -t T [-o O] -oname ONAME

Process a tcpdump -n trace and convert it to the following format: %H:%M:%S.%µS IP_SRC > IP_DEST LENGTH

optional arguments:
  -h, --help    show this help message and exit
  -t T          Path to the _ascii_ trace file
  -o O          Output directorty, default .
  -oname ONAME  Output filename
```

The converted tcpdump file named tcpls_migration_pruned.log, and the
file tcpls_migration_goodput then needs to be feeded to the plot script.
You can simply move them in pretty_plotify/results/ directory on the
paper's repository. Do not forget to either edit the --event_at in
plots.sh, or to call yourself plot_aggregate.py that resides in the paper's [pretty_plotify](https://github.com/frochet/tcpls_conext21/tree/conext21/pretty_plotify) directory. Here's one example:

```bash
python3 plot_aggregate.py --goodput $input/tcpls_migration_goodput --tcpdump $input/tcpls_migration_pruned.log --oname $output/migration --ext pdf -i 0.1 --event_at 14:55:28.854711 14:55:30.142117 14:55:33.569810 14:55:34.752775 --event_text "New Stream on Path 1" "Stream closed and Path 0 Closed" "0-RTT Conn + New Stream on Path 0" "Stream Closed and Path 1 closed" --event_pos 2 7 2 7
```

