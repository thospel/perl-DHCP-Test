# NAME

dhcp\_test - Do a test DHCP exchange

# SYNOPSIS

```
dcp_test [-v|--verbose] [-k|--keep] [-m|-mac [<string>]] [--xid <INT>]
         [-H|--hostname [<string>]] [-e|--expect <IP>] [--fou <ADDRESS>]
         [-s|--server <IP>] [-T|--track] [-i|--interface <string>]
         [-b|--broadcast] [-u|--unicast] [-g|--gateway [<IP>]]
         [-l|--listen <ADDRESS>] [-t|--timeout <FLOAT>] [-r|--retries <INT>]
dhcp_test [--version] [-U | --unsafe] [-h | --help]
```

# DESCRIPTION

**dhcp\_test** does a complete exchange with a DHCP server.
Send DHCPDISCOVER, receive DHCPOFFER, send DHCPREQUEST, receive DHCPACK and
send DHCPRELEASE.

# OPTIONS

Valid options are:

- -v, --verbose

    Print details about the DHCP exchange

- -k, --keep

    Do not release the IP address at the end of the exchange
    (don't send the DHCPRELEASE).

- -H, --hostname _STRING_

    Propose this hostname to the DHCP server. If this option is given but the _STRING_ value is absent or empty it will use the name of the host the program runs
     on.

- -m, --mac _STRING_

    The MAC address what will be sent with the DHCPDISCOVER request. If this option
    is not given the MAC address of the sending interface will be used.

    The program currently only supports ethernet.

    The _STRING_ is a case insensitive hexadecimal string and may use colons,
    periods or spaces as separators. Separated groups are left padded with a `0`
    if their length is odd. So

    ```
    --mac "1 Ab::6. 3dE 12"
    ```

    will be interpreted the same as `01AB0603XE12` or `01:AB:06:03:XE:12`

    As seen in this example you can also set digits in _STRING_ to the placeholder
    `X`. These nibbles will be replaced by somewhat random values. This allows you
    to generate probably unique MACs. For example

    ```
    --mac BA:D1:XX:XX:XX:XX
    ```

    might generate a MAC address like `BA:D1:28:F8:6C:1B` which should hopefully be
    unique among recent `dhcp_test` requests and should not be in use by any real
    device because MAC addresses with the second least significant bit of the most
    significant octet set are locally administered for unicast:

    ```
    x2:xx:xx:xx:xx:xx
    x6:xx:xx:xx:xx:xx
    xA:xx:xx:xx:xx:xx
    xE:xx:xx:xx:xx:xx
    ```

    Something else on your net may also use locally administered MAC addresses
    (e.g. some embedded devices), so make sure to pick a prefix that doesn't clash.

    Also take care when combining MAC placeholders with the [--keep](#keep) option
    because you may exhaust the DHCP server IP addresses pool.

- --xid _INT_

    Use _INT_ as transaction identifier. Can also be given as an _IP_ which is
    then converted to number. If not given an appropiate value is generated
    internally.

    Transaction IDss are used to match DHCP responses with DHCP requests
    (among other things. the program also checks for a MAC address match).

    This value will be used for the DHCPDISCOVER request. After selecting a
    DHCPOFFER response the value is increased by _1_ (wrapped) and the result is
    used for DHCPREQUEST and DHCPRELEASE.

- -e, --expect _IP_

    When DHCPDISCOVER requests are broadcast multiple DHCP servers can answer.
    By default the first DHCPOFFER received will be selected to go ahead with.
    If this option is given only a DHCPOFFER from the DHCP server with the given
    _IP_ will be selected.

    The sender of the selected DHCPOFFER (irrespective of the value of this option)
    will always be used for DHCP response selection in the following steps.

    All DHCP responses (not just DHCPOFFER) are checked for coming from port 67
    (irrespective of the value of this option.

- -s, --server _IP_

    Send DHCP requests to the given _IP_. If this option is not given it will
    use the broadcast address _255.255.255.255_.

    Notice that [--expect](#expect) option may still be needed since since the
    answers don't always come from from server _ip_, e.g, with a multihomed DHCP
    server.
    And there is always a chance that some other DHCP server sends a response which
    just happens to match all relevant properties (mostly MAC address and
    transaction ID). This is less theoretical than it may seem because some DHCP
    servers snoop network traffic and respond to requests even if the request is
    specifically not addressed to them.

- -i, --interface _string_

    Bind the sending socket to the named interface (e.g. _eth0_). This can be
    important if you need the packets to be sent over a specific interface.
    If this option is not given the operating system will typically send requests
    over the interface that the routing table will select for the
    [server](#server) value.

- -T, --track

    This options modifies the meaning [--server](#server) value.

    The DHCPDISCOVER will still be send to the given [--server](#server) address,
    but all subsequent requests will be directly sent to the DHCP server that sent
    the selected DHCPOFFER response.

- -b, --broadcast

    This option defaults to true if no [--server](#server) option is give. Otherwise
    it defaults to false.

    If this option is true the broadcast flag is applied to the socket sending the
    DHCPDISCOVER request. This is needed on most operating systems to be allowed
    to send a broadcast packet, but this will usually need special permissions
    (like being `root` on unix).

    The flag is also used for subsequent requests except if the [--track](#track)
    option is given. In that last case the packets are directly sent to the DHCP
    server whose DHCPOFFER was selected, so no broadcast flag is needed.

    This option controls request packets. So don't confuse this with the
    [--unicast](#unicast) option which controls response packets.

- -u, --unicast

    By default a flag is set in each DHCP request which requests that the response
    gets sent as a broadcast.

    If this option is given that flag is not set and as a result the response will
    be sent directly to the IP address that gets assigned by the DHCP server. Unless
    this is an IP address of the host on which this program is running the program
    will not see the response and the DHCP exchange will fail. So only use this
    option if you have some cunning plan.

    The option will be ignored if the program acts as a DHCP relay (using the
    [--gateway](#gateway) option)

    This option (indirectly) controls response packets. So don't confuse this with
    the [--broadcast](#broadcast) option which controls request packets.

- -g, --gateway _IP_

    The program will behave like a DHCP relay. All requests will use the given _IP_
    as the gateway address. The _IP_ argument is optional. If this option is given
    without argument or with an empty argument it will use a local IP address instead (the IP address that
    would be used as source for packets to [sender](#sender)).

    If this option is used the DHCP server will send its responses back to _IP_.
    So if this is not a local IP the program will normally not see the DHCP response
    so only do that if you have a cunning plan.

    Notice that this option is the way you tell a DHCP server to select an address
    from a different subnet than the one with the DGCP server address.

- --fou _ADDRESS_

    Send packet using FOU encapsulation (Foo over UDP).

    _ADDRESS_ can be given as _HOST:PORT_ or as just a port (number or name) in
    which case the host defaults to `127.0.0.1`.

    If this option is given the outgoing packet is encapsulated and then sent to
    _ADDRESS_ which is responsible for decapsulating it.

    This option allows the program to send packets that it otherwsie cannot
    (because the user lacks permission to construct such packets).

- -l, --listen _ADDRESS_

    Listen for responses on _ADDRESS_.

    If this option is not given, it defaults to _68_ unless the
    [gateway](#gateway) option is given in which case it will default to _67_.
    On most operating systems these low port numbers will usually need special
    permissions (like being `root` on unix).

    _ADDRESS_ can be given as just a port (number or name) in which case the
    program will listen on all addresses or in the form of _HOST:PORT_ in which
    case it will listen on that specific _IP_ and _PORT_ combination.

    Since you have no control over to which port the DHCP server will send its
    responses using this option with a different port will normally mean the program
    won't see the response so only use this option if you have a cunning plan.

    Packets received on this interface are first checked for FOU encapsulation
    (irrespective of the use of the [--fou](#fou) option). If they are encapsulated
    the packet is first decapsulated before further processing.

- -r, --timeout _FLOAT_

    After sending a DHCP request the program will wait for _FLOAT_ seconds for
    a resonse. Defaults to _1.5_.

- -r, --retries _INT_

    If the DHCP response times out the program will retry _INT_ more times.
    Defaults to _2_ (giving a total of 3 attempts)

- -h, --help

    Show this help.

- -U, --unsafe

    Allow even root to run the perldoc.
    Remember, the reason this is off by default is because it **IS** unsafe.

- --version

    Print version info.

All _IP_ values can also be given as names that will then be resolved.

# EXAMPLE

Simplest use: Do a broadcast, get an IP address assigned and release it

```
dhcp_test
```

The same but with more details about the steps:

```
dhcp_test -v
```

Do the same thing but don't release the assigned IP address at the end:

```
dhcp_test -k
```

The same but function as a DHCP relay:

```
dhcp_test -g
```

Do the DHCP exchange only with a specific DHCP server without broadcast:

```
dhcp_test -s IP
```

Do normal DHCP broadcasts, but only accept offers from a specific DHCP server:

```
dhcp_test -e IP
```

A very complex example:

Send a request on interface `eth0` (-i) to `0.0.0.1` (-s) for a host with
randomly generated MAC address `BA:D1:XX:XX:XX:XX` (-m) and proposed hostname
`pluto` (-H) as a DHCP relay that expects an answer to 10.254.0.14 (-g). Only
accept answers from `10.253.0.8` (-e). Once the DHCP server gives us an IP
address we hold one to it (-k). Send using FOU over port 1237 and listen for
(FOU) answers on port `1236` (-l)

```
dhcp_test -s 0.0.0.1 -e 10.253.0.8 -m BA:D1:XX:XX:XX:XX -H pluto -k -g 10.254.0.14 -i eth0 -l 1236 --fou 1237
```

We assume here we are running on `10.254.0.8` which is also the host with a
DHCP server (which snoops the otherwise meaningless packets to `0.0.0.1`). So
we won't seee the answer to `10.254.0.14` and would normally time out. On linux
we can set up a FOU tunnel that catches the response:

```perl
# Set up FOU tunnel. Notice that we listen on the output port of the tunnel
ip link add name fou1 type ipip remote 127.0.0.1 local 127.0.0.1 ttl 225 encap fou encap-sport auto encap-dport 1236
ip addr add 10.253.4.1/24 dev fou1
# Decapsulator
ip fou add port 1237 ipproto 4 local 127.0.0.1

# Allow these weird outgoing FOU packets
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.fou1.rp_filter=0

# Match DHCP replies about MAC address BA:D1:XX:XX:XX:XX
# Leave operational DHCP replies alone
iptables -t mangle -A OUTPUT -p udp --dport 67 --sport 67 -m u32 --u32 "4&0x1FFF=0 && 0>>22&0x3C@34&0xffff=0xbad1" -j MARK --set-mark 17

# Make marked packets use routing plane 101
ip rule add fwmark 17 lookup 101

# Route everything in routing plane 101 to the FOU tunnel:
# ip route add default via 10.253.4.1 table 101
```

# BUGS

Only supports IPV4

# SEE ALSO

[dhcpd(8)](http://man.he.net/man8/dhcpd),

# AUTHOR

Ton Hospel, <DHCP-Test@ton.iguana.be>

# COPYRIGHT AND LICENSE

Copyright (C) 2021 by Ton Hospel

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.
