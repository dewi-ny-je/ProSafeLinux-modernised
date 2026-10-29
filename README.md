# ProSafeLinux (psl-cli.py)

Query and set data on Netgear ProSafe Plus switches (GS105E, GS108E, GS116E
and friends) from Linux or macOS, using the NSDP protocol that Netgear's
"ProSafe Plus Utility" speaks.

These are known to work:
 * GS105E 1.02.04
 * GS108Ev2 1.00.12
 * GS108Ev3 2.06.08EN (replies come via unicast)

## Requirements

Python 3.9 or newer and nothing else: no third-party packages are needed.
Tested on Linux (Ubuntu) and macOS, including the Python 3.9 that ships with
Apple's command line tools.

## Using psl-cli.py

    usage: psl-cli.py [-h] [--interface INTERFACE] [--debug]
                      [--timeout TIMEOUT]
                      {discover,exploit,query,query_raw,set} ...

 * By default the interface carrying the default route is used (for example
   `enp3s0` on Ubuntu or `en0` on macOS). Pass `--interface` to choose another
   one, e.g. a USB Ethernet adapter on a Mac.
 * Older switch firmware (before 2018?) returns responses to the broadcast
   address, newer firmware returns them to the sender. Both are handled.
 * macOS does not allow sending to 255.255.255.255, so there discovery falls
   back to the subnet broadcast address of the interface (e.g.
   192.168.1.255). On macOS 15 and later, allow "Local Network" access for
   your terminal app in System Settings > Privacy & Security if nothing is
   found.
 * The default timeout is 0.1 seconds; if a switch does not answer, try
   `--timeout 1`.
 * Password hashing is picked automatically from what the switch reports:
   a fixed XOR or the nonce based 32/64 bit hashes of recent firmware. Old
   firmware only accepts plain text passwords; because that reply could be
   forged by anyone on the network, plain text is only sent when you add
   `--allow-plaintext`.

## Examples

Gives an overview of all available options

    ./psl-cli.py --help

Discover all ProSafe switches on the local network

    ./psl-cli.py --interface eth1 discover

Set 802.1Q VLAN VID for port 4 to 1

    ./psl-cli.py  set --passwd "password" --mac B0:B9:8A:57:F6:56 --vlan_pvid 4 1

Query all ports for their 802.1Q VLAN port VID

    ./psl-cli.py query --mac B0:B9:8A:57:F6:56 vlan_pvid

## Testing

`tests/smoke_test.sh` runs the command line tool against a small simulated
switch on the local machine (unicast and broadcast replies, every password
scheme). `tests/check_interfaces.py` checks that the interface detection agrees
with `ip`/`ifconfig`. Both run in CI on Ubuntu and macOS.

## Known issues

Newer switches that have web servers may have "Switch Management Mode" set to
"Web browser only", which will result in the switch only responding to
discovery requests. To use this software, log in to the web UI and set "Switch
Management Mode" to "Web browser and Plus Utility".

## Wireshark

`wireshark/nsdp.lua` is a dissector for the protocol.

## Help wanted

Feel free to fork the code and send pull requests.

The original author found a security problem with these switches, described
(in German) here:

http://www.linux-magazin.de/Blogs/Insecurity-Bulletin/Gastbeitrag-Security-by-Obscurity-bei-Netgear-Switches
http://www.linux-magazin.de/Ausgaben/2012/10/Switch

## Forks merged into this one

 * https://github.com/rhulme/ProSafeLinux (Richard Hulme)
 * https://github.com/Z3po/ProSafeLinux (Sebastian Cabrera, Steven Bytnar)
 * https://github.com/flucas1/ProSafeLinux (Fernando Lucas)

## Other similar projects

https://github.com/Z3po/Netgearizer (We are merging code together.)

## Authors

* Asbjørn Sloth Tønnesen 
* Lars Dennis Renneberg Andersen
* Svenne Krap
* Shane Kerr
* Sven Anders
* Steven Bytnar
* Richard Hulme
* Mario Haustein
* Fernando Lucas

See also: http://git.asbjorn.biz/?p=gs105e.git;a=summary

It would be nice if you pay attribution to this project if you use this code.

If you like the projekt, you may [![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=tabacha&url=https://github.com/tabacha/ProSafeLinux&title=ProSafeLinux&language=&tags=github&category=software)
