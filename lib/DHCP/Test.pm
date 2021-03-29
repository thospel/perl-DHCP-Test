package DHCP::Test;
use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
use Socket qw(INADDR_ANY PF_INET SOCK_DGRAM SOL_SOCKET SO_BROADCAST
              pack_sockaddr_in unpack_sockaddr_in inet_ntoa inet_aton);
use IO::Interface::Simple;
use constant {
    # This is the linux value. Can/will be different on a different OS
    SO_BINDTODEVICE	=> 25,
    BOOTPS		=> getservbyname("bootps", "udp") // 67,
    BOOTPC		=> getservbyname("bootpc", "udp") // 68,
    PROTO_UDP		=> getprotobyname("udp") // 17,

    BLOCK_SIZE		=> int(2**16),

    BOOTREQUEST		=> 1,
    BOOTREPLY		=> 2,

    HW_ETHERNET		=>  1,
    COOKIE		=> 0x63825363,
    DISCOVER		=>  1,
    OFFER		=>  2,
    REQUEST		=>  3,
    DECLINE		=>  4,
    ACK			=>  5,
    NAK			=>  6,
    RELEASE		=>  7,
    INFORM		=>  8,
    FORCERENEW		=>  9,
    LEASEQUERY		=> 10,
    LEASEUNASSIGNED	=> 11,
    LEASEUNKNOWN	=> 12,
    LEASEACTIVE		=> 13,
    BULKLEASEQUERY	=> 14,
    LEASEQUERYDONE	=> 15,
    ACTIVELEASEQUERY	=> 16,
    LEASEQUERYSTATUS	=> 17,
    TLS			=> 18,
    FLAG_BROADCAST	=> 0x8000,

    # DHCP Options
    OPTION_PAD		=>   0,
    OPTION_MASK		=>   1,
    OPTION_TIME_OFFSET	=>   2,
    OPTION_ROUTER	=>   3,
    OPTION_TIME_SERVER	=>   4,
    OPTION_DNS		=>   6,
    OPTION_HOSTNAME	=>  12,
    OPTION_DOMAIN	=>  15,
    OPTION_FORWARDING	=>  19,
    OPTION_TTL		=>  23,
    OPTION_BROADCAST	=>  28,
    OPTION_NTP		=>  42,
    OPTION_REQUEST_IP	=>  50,
    OPTION_LEASE_TIME	=>  51,
    OPTION_OVERLOAD	=>  52,
    OPTION_TYPE		=>  53,
    OPTION_SERVER	=>  54,
    OPTION_REQUEST_LIST	=>  55,
    OPTION_MESSAGE	=>  56,
    OPTION_SIZE_MAX	=>  57,
    OPTION_RENEWAL_TIME	=>  58,
    OPTION_REBIND_TIME	=>  59,
    OPTION_BOOT_SERVER	=>  66,
    OPTION_BOOT_FILE	=>  67,
    OPTION_SMTP		=>  69,
    OPTION_NNTP		=>  71,
    OPTION_WWW		=>  72,
    # I use 150 to set the GRUB configuration path name (semi standard)
    OPTION_GRUB		=> 150,
    # OPTION_PXE_LINUX	=> 208,
    # I use 208 to send http-proxy (with 2 ports) on my home network (private)
    OPTION_PROXY	=> 224,
    # I use 209 to set the socks server home network (private)
    OPTION_SOCKS	=> 225,
    OPTION_END		=> 255,

    TYPE_ADDR		=>  1,
    TYPE_IP		=>  2,
    TYPE_IPS		=>  3,
    TYPE_STRING		=>  4,
    TYPE_INT		=>  5,
    TYPE_UINT8		=>  6,
    TYPE_UINT8S		=>  7,
    TYPE_UINT16		=>  8,
    TYPE_UINT		=>  9,
    TYPE_FLAG		=> 10,
    TYPE_IP_PORT_PORT	=> 11,

    # Request list
    REQUEST_SUBNET		=>   1,
    REQUEST_TIME		=>   2,
    REQUEST_ROUTER		=>   3,
    REQUEST_DNS			=>   6,
    REQUEST_HOSTNAME		=>  12,
    REQUEST_DOMAIN		=>  15,
    REQUEST_BROADCAST		=>  28,
    REQUEST_NTP			=>  42,
    REQUEST_NETBIOS_NS		=>  44,
    REQUEST_NETBIOS_SCOPE	=>  47,
    REQUEST_MTU			=>  26,
    REQUEST_DOMAIN_SEARCH	=> 119,
    REQUEST_ROUTE_STATIC	=> 121,
};

our $verbose;
our $separator = "===============";
use Exporter::Tidy
    socket  => [qw(BOOTPS BOOTPC PROTO_UDP SO_BINDTODEVICE)],
    options => [qw(OPTION_MASK OPTION_TIME_OFFSET OPTION_ROUTER
                   OPTION_TIME_SERVER OPTION_DNS OPTION_HOSTNAME OPTION_DOMAIN
                   OPTION_FORWARDING OPTION_TTL OPTION_BROADCAST OPTION_NTP
                   OPTION_REQUEST_IP OPTION_LEASE_TIME OPTION_OVERLOAD
                   OPTION_TYPE OPTION_SERVER OPTION_REQUEST_LIST OPTION_MESSAGE
                   OPTION_SIZE_MAX OPTION_RENEWAL_TIME OPTION_REBIND_TIME
                   OPTION_BOOT_SERVER OPTION_BOOT_FILE OPTION_SMTP OPTION_NNTP
                   OPTION_WWW OPTION_GRUB OPTION_PROXY OPTION_SOCKS OPTION_END)],
    other => [qw($verbose $separator
                 DISCOVER OFFER REQUEST ACK NAK RELEASE
                 packet_send options_parse packet_receive)];

my $request_list =
    pack("W*",
         REQUEST_SUBNET,
         REQUEST_BROADCAST,
         REQUEST_TIME,
         REQUEST_ROUTER,
         REQUEST_DOMAIN,
         REQUEST_DNS,
         REQUEST_DOMAIN_SEARCH,
         REQUEST_HOSTNAME,
         REQUEST_NETBIOS_NS,
         REQUEST_NETBIOS_SCOPE,
         REQUEST_MTU,
         REQUEST_ROUTE_STATIC,
         REQUEST_NTP);

my %option_types = (
    OPTION_BOOT_FILE()		=> [TYPE_STRING, "boot_file"],
    OPTION_BOOT_SERVER()	=> [TYPE_STRING, "boot_server"],
    OPTION_BROADCAST()		=> [TYPE_IP, "braodcast"],
    OPTION_DNS()		=> [TYPE_IPS, "dns", "DNS"],
    OPTION_DOMAIN()		=> [TYPE_STRING, "domain"],
    OPTION_FORWARDING()		=> [TYPE_FLAG, "forwarding"],
    OPTION_GRUB()		=> [TYPE_STRING, "grub"],
    OPTION_HOSTNAME()		=> [TYPE_STRING, "hostname"],
    OPTION_LEASE_TIME()		=> [TYPE_UINT, "lease_time"],
    OPTION_MASK()		=> [TYPE_IP, "mask"],
    OPTION_MESSAGE()		=> [TYPE_STRING, "message"],
    OPTION_NNTP()		=> [TYPE_IPS, "nntp", "NNTP"],
    OPTION_NTP()		=> [TYPE_IPS, "ntp", "NTP"],
    OPTION_OVERLOAD()		=> [TYPE_UINT8, "overload"],
    OPTION_PROXY()		=> [TYPE_IP_PORT_PORT, "proxy"],
    OPTION_REBIND_TIME()	=> [TYPE_UINT, "rebind_time"],
    OPTION_RENEWAL_TIME()	=> [TYPE_UINT, "renewal_time"],
    OPTION_REQUEST_IP()		=> [TYPE_IP, "request_ip"],
    OPTION_REQUEST_LIST()	=> [TYPE_UINT8S, "request_list"],
    OPTION_ROUTER()		=> [TYPE_IP, "router"],
    OPTION_SERVER()		=> [TYPE_ADDR, "server", ""],
    OPTION_SIZE_MAX()		=> [TYPE_UINT16, "size_max", "Max Packet Size"],
    OPTION_SMTP()		=> [TYPE_IPS, "smtp", "SMTP"],
    OPTION_SOCKS()		=> [TYPE_IP, "socks"],
    OPTION_TIME_OFFSET()	=> [TYPE_INT, "time_offset"],
    OPTION_TIME_SERVER()	=> [TYPE_IPS, "time_server"],
    OPTION_TTL()		=> [TYPE_UINT8, "ttl", "TTL"],
    OPTION_TYPE()		=> [TYPE_UINT8, "message_type", ""],
    OPTION_WWW()		=> [TYPE_IPS, "www", "WWW"],
);
my %option_names;
while (my ($tag, $option_type) = each %option_types) {
    die "Assertion: Duplicate option name '$option_type->[1]'" if
        exists $option_names{$option_type->[1]};
    $option_type->[3] = $tag;
    $option_names{$option_type->[1]} = $option_type;
}

sub options_build {
    my (%options) = @_;

    my $str = "";
    for my $name (keys %options) {
        eval {
            my $value= $options{$name};
            my $option_type = $option_names{$name} //
                croak "No handler for option $name";
            my ($otype, undef, $disply_name, $tag) = @$option_type;
            if ($otype == TYPE_UINT8) {
                $value =~ /^[+-]?\d+\z/a || croak "Not a number";
                $value = int($value);
                croak "$value < 0" if $value < 0;
                croak "$value > 255" if $value > 255;
                $value = pack("W", $value);
            } elsif ($otype == TYPE_UINT16) {
                $value =~ /^[+-]?\d+\z/a || croak "Not a number";
                $value = int($value);
                croak "$value < 0" if $value < 0;
                croak "$value > 65535" if $value > 65535;
                $value = pack("n", $value);
            } elsif ($otype == TYPE_ADDR) {
                length $value == 4 || croak "Invalid IPv4 address size";
            } elsif ($otype == TYPE_STRING) {
            } elsif ($otype == TYPE_IP) {
                $value = inet_aton($value) // croak "Invalid ip '$value'";
            } else {
                die "Option type $otype not implemented (yet)";
            }
            $str .= pack("WW/a*", substr($value, 0, 255, "")) while
                length $value >= 256;
            $str .= pack("WW/a*", $tag, $value);
        };
        die "Option $name: $@" if $@;
    }
    return $str . pack("W", OPTION_END);
}

sub packet_send {
    my ($type, $interface, $target, $xid, $gateway_ip, $mac, %options) = @_;

    my $ciaddr = INADDR_ANY;
    if ($type == RELEASE) {
        my $client_ip = delete $options{request_ip} //
            croak "Missing mandatory option 'request_ip'";
        $ciaddr = inet_aton($client_ip) // croak "Invalid 'request_ip' value";
    }
    socket(my $sender, PF_INET, SOCK_DGRAM, PROTO_UDP) ||
        die "Could not create socket: $^E";
    setsockopt($sender, SOL_SOCKET, SO_BROADCAST, 1) ||
        die "Could not setsockopt SO_BROADCAST: $^E";
    my $if;
    if ($interface) {
        setsockopt($sender, SOL_SOCKET, SO_BINDTODEVICE,
                   pack("Z*", $interface)) ||
                       die "Could not setsockopt SO_BINDTODEVICE('$interface'): $^E";
        $if = IO::Interface::Simple->new($interface) //
            die "Could not get properties of interface '$interface'" if !$mac;
    }
    # setsockopt($sender, SOL_SOCKET, SO_REUSEADDR, 1) ||
    #    die "Could not setsockopt SO_REUSEADDR: $^E";
    # my $from = pack_sockaddr_in(BOOTPC, INADDR_ANY);
    # bind($sender, $from) or die "Could not bind: $^E";
    my $to   = pack_sockaddr_in(BOOTPS, $target);
    connect($sender, $to) or die "Could not connect: $^E";
    my $from = getsockname($sender) // die "Could not getsockname: $^E";
        my ($port, $from_addr) = unpack_sockaddr_in($from);
        my $from_ip = inet_ntoa($from_addr);
    $gateway_ip = $from_ip if defined $gateway_ip && $gateway_ip eq "";
    if (!$mac) {
        $if //= IO::Interface::Simple->new_from_address($from_ip) //
            die "Could not get local interface for IP $from_ip";
        $mac = $if->hwaddr //
            die "Could not get MAC address of interface $if";
        my @mac = map hex, split /:/, $mac;
        @mac == 6 || die "Invalid MAC length";
        $_ <= 0xff || die "Invalid value in MAC" for @mac;
        $mac = pack("W*", @mac);
    }

    my $buffer = pack("W4Nnna4x4x4a4a16x192N",
		      BOOTREQUEST, # Message opcode
		      HW_ETHERNET, # Hardware type
		      6,           # Hardware addr length (6 bytes) <= 16
		      0,           # Max Hops
		      $xid,
		      0,              # secs
                      FLAG_BROADCAST, # flags
                      $ciaddr,
                      $gateway_ip ? inet_aton($gateway_ip) : INADDR_ANY,
                      $mac,
                      COOKIE,
                  );
    # Probably should add a check for overlong packets...
    $buffer .= options_build(size_max => 406,
                                   %options,
                                   message_type => $type);
    #my $pad = PACKET_SIZE - length $buffer;
    #die "Packet too long" if $pad < 0;
    my $rc = syswrite($sender, $buffer) //
        die "Could not send message: $^E";
    length $buffer == $rc ||
        die "Sent truncated DHCP message\n";
    return $mac;
}

sub options_parse {
    my ($options, $string) = @_;

    my %accu;
    while ($string ne "") {
        my $tag = ord substr($string, 0, 1, "");
        next if $tag == OPTION_PAD;
        last if $tag == OPTION_END;
        my ($value, $pos) = unpack("W/a*.", $string);
        $accu{$tag} = exists $accu{$tag} ? $accu{$tag} . $value : $value;
        substr($string, 0, $pos, "");
    }
    while (my ($tag, $value) = each %accu) {
        if (my $option_type = $option_types{$tag}) {
            my ($otype, $name, $disply_name) = @$option_type;
            if (!defined $disply_name) {
                $disply_name = ucfirst($name);
                $disply_name =~ s/_(.)/ \u$1/g;
            }
            if ($otype == TYPE_IP) {
                length $value == 4 || die "Unexpected $name length";
                $options->{$name} = inet_ntoa($value);
            } elsif ($otype == TYPE_IP_PORT_PORT) {
                length $value == 8 || die "Unexpected $name length";
                my ($addr, $p1, $p2) = unpack("a4nn", $value);
                $options->{$name} = [inet_ntoa($addr), $p1, $p2];
            } elsif ($otype == TYPE_IPS) {
                length($value) % 4 == 0 || die "Unexpected $name length";
                $options->{$name} = [map inet_ntoa($_), unpack("(a4)*", $value)];
            } elsif ($otype == TYPE_ADDR) {
                length $value == 4 || die "Unexpected $name length";
                $options->{$name} = $value;
            } elsif ($otype == TYPE_STRING) {
                $options->{$name} = $value;
            } elsif ($otype == TYPE_UINT) {
                length $value == 4 || die "Unexpected $name length";
                $options->{$name} = unpack("N", $value);
            } elsif ($otype == TYPE_UINT8) {
                length $value == 1 || die "Unexpected $name length";
                $options->{$name} = unpack("W", $value);
            } elsif ($otype == TYPE_FLAG) {
                length $value == 1 || die "Unexpected $name length";
                $options->{$name} =
                    $value eq "\x0" ? 0 :
                    $value eq "\x1" ? 1 :
                    die "Invalid $name flag value";
            } else {
                die "Assertion: Unimplemented option type $option_type->[0]";
            }
            if ($verbose && $disply_name ne "") {
                if (ref $options->{$name} eq "ARRAY") {
                    print "$disply_name: @{$options->{$name}}\n";
                } else {
                    print "$disply_name: $options->{$name}\n";
                }
            }
        } else {
            $value = unpack("H*", $value);
            print "Option $tag: $value\n" if $verbose;
        }
    }
}

sub packet_receive {
    my ($socket, $xid, $expect_addr, $mac) = @_;

    while (1) {
        my $server = recv($socket, my $buffer, BLOCK_SIZE, 0) //
            die "Could not sysread: $^E";
        my ($server_port, $server_addr) = unpack_sockaddr_in($server) or
            die "Could not decode UDP sender address";

        my ($op, $hw_type, $hw_len, $hops,
            $reply_xid, $secs, $flags,
            $client_addr, $your_addr, $boot_addr, $gateway_addr,
            $hw_addr,
            $server_name, $boot_file,
            $cookie, $options)
            = unpack("W4Nnna4a4a4a4a16a64a128Na*", $buffer);

        # This happens. We will at least see our own broadcast
        $op == BOOTREPLY || next;

        $cookie && $cookie == COOKIE || next;
        $hw_addr = substr($hw_addr, 0, $hw_len);
        $hw_addr eq $mac || next;
        printf "%s\nReply (length %d) from %s:%d for %s\n",
            $separator, length $buffer, inet_ntoa($server_addr), $server_port, unpack("H*", $hw_addr) if $verbose;
        $hw_type == HW_ETHERNET || next;
        $reply_xid == $xid || next;
        !$expect_addr || $server_addr eq $expect_addr || next;
        my %option = (
            server_addr	=> $server_addr,
            server_ip	=> inet_ntoa($server_addr),
            server_port	=> $server_port,
            xid		=> $reply_xid,
            xid_ip	=> inet_ntoa(pack("N", $reply_xid)),
            client_addr	=> $client_addr,
            client_ip	=> inet_ntoa($client_addr),
            your_addr	=> $your_addr,
            your_ip	=> inet_ntoa($your_addr),
            boot_addr	=> $boot_addr,
            boot_ip	=> inet_ntoa($boot_addr),
            gateway_addr=> $gateway_addr,
            gateway_ip	=> inet_ntoa($gateway_addr),
            hw_addr	=> $hw_addr,
        );
        defined $options || die "Truncated DHCP reply";
        my $hw = unpack("H*", $option{hw_addr});
        $hw =~ s/(..)\B/$1:/g;
        print <<"EOF" if $verbose
op=$op, hw_type=$hw_type, hw_len=$hw_len, hops=$hops
xid=$option{xid_ip} secs=$secs, flags=$flags
client IP $option{client_ip}
Your   IP $option{your_ip}
Server IP $option{server_ip}
Gate   IP $option{gateway_ip}
MAC    $hw
EOF
            ;
        options_parse(\%option, $options);
        if ($option{overload}) {
            $option{overload} <= 3 ||
                die "Invalid overload value '$option{overload}'";
            if ($option{overload} & 1) {
                # Untested since none of my DHCP servers do this
                # First 'file'
                options_parse(\%option, $boot_file);
                $boot_file = undef;
            }
            if ($option{overload} & 2) {
                # Untested since none of my DHCP servers do this
                # Second 'sname'
                options_parse(\%option, $server_name);
                $server_name = undef;
            }
        }
        if ($server_name) {
            $option{server_name} = unpack("Z*", $server_name);
            print "Server Name: $option{server_name}\n" if $verbose;
        }
        if ($boot_file) {
            $option{boot_file} = unpack("Z*", $boot_file);
            print "Boot File: $option{boot_file}\n" if $verbose;
        }
        exists $option{server} || die "Missing server identifier in DHCP reply";
        $option{server} eq $server_addr || die "Inconsistent server";

        # On my net the router can send a NAK even though the router does
        # not mot match the server identifier. So we should do a perl "next" if
        # server identifier does not match request

        exists $option{message_type} || die "No reply message type";
        return \%option;
    }
}

1;
