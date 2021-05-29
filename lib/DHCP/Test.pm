package DHCP::Test;
use strict;
use warnings;

our $VERSION = "1.000";

use Carp;
use Socket qw(INADDR_ANY PF_INET SOCK_DGRAM SOL_SOCKET SO_BROADCAST
              IPPROTO_IP IP_TTL
              pack_sockaddr_in unpack_sockaddr_in inet_ntoa inet_aton);
use IO::Interface::Simple;
use Time::HiRes qw(clock_gettime CLOCK_MONOTONIC );
use Errno qw(EINTR);
use Data::Dumper;

use constant {
    # The linux value is 25. Can/will be different on a different OS
    SO_BINDTODEVICE	=> Socket::SO_BINDTODEVICE(),
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

    MULTICAST_BEGIN => inet_aton("224.0.0.0") // die("Assertion: Bad address"),
    # multicast range *excludes* this END address
    MULTICAST_END   => inet_aton("240.0.0.0") // die("Assertion: Bad address"),
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
    message_types => [
        qw(DISCOVER OFFER REQUEST DECLINE ACK NAK RELEASE INFORM
           FORCERENEW LEASEQUERY LEASEUNASSIGNED LEASEUNKNOWN LEASEACTIVE
           BULKLEASEQUERY LEASEQUERYDONE ACTIVELEASEQUERY LEASEQUERYSTATUS TLS)],
    other => [qw($verbose $separator
                 parse_udp_address packet_send options_parse packet_receive
                 message_type mac_string string_from_value)];

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

my %message_type = (
    DISCOVER()		=> "DISCOVER",
    OFFER()		=> "OFFER",
    REQUEST()		=> "REQUEST",
    DECLINE()		=> "DECLINE",
    ACK()		=> "ACK",
    NAK()		=> "NAK",
    RELEASE()		=> "RELEASE",
    INFORM()		=> "INFORM",
    FORCERENEW()	=> "FORCERENEW",
    LEASEQUERY()	=> "LEASEQUERY",
    LEASEUNASSIGNED()	=> "LEASEUNASSIGNED",
    LEASEUNKNOWN()	=> "LEASEUNKNOWN",
    LEASEACTIVE()	=> "LEASEACTIVE",
    BULKLEASEQUERY()	=> "BULKLEASEQUERY",
    LEASEQUERYDONE()	=> "LEASEQUERYDONE",
    ACTIVELEASEQUERY()	=> "ACTIVELEASEQUERY",
    LEASEQUERYSTATUS()	=> "LEASEQUERYSTATUS",
    TLS()		=> "TLS",
);

my $IP_VERSION = 4;
my $IHL = 5;
my $UDP_HEADER = 8;
my $DF = 2;
my $TTL = 64;
my $TTL_LOW = 2;

sub string_from_value {
    local $Data::Dumper::Indent	  = 0;
    local $Data::Dumper::Sortkeys = 1;
    local $Data::Dumper::Useqq	  = 1;
    local $Data::Dumper::Trailingcomma = 0;
    # local $Data::Dumper::Varname  = "VAR";
    local $Data::Dumper::Terse = 1;
    local $Data::Dumper::Quotekeys = 0;
    local $Data::Dumper::Sparseseen = 1;
    return Dumper(shift);
}

sub mac_string {
    my $mac = uc unpack("H*", shift);
    $mac =~ s/(..)\B/$1:/g;
    return $mac;
}

sub parse_udp_address {
    my ($str, $context, $default_host, $default_port, $prefer_host) = @_;

    my ($host, $port) = $prefer_host && $str !~ /^[0-9]+\z/ ?
        $str =~ /^(.*?)(?::([^:]*))?\z/ :
        $str =~ /^(?:(.*):)?([^:]*)\z/ or
        die "Could not parse $context '$str'\n";
    if (!defined $host) {
        $host = $default_host // "127.0.0.1" || "0.0.0.0";
    } elsif ($host eq "") {
        $host = $default_host // "0.0.0.0" || "127.0.0.1";
    }
    my $addr = inet_aton($host) || die "Could not resolve $context '$host'\n";
    $port = !defined $port || $port eq "" ? $default_port // die "No port in $context '$str'\n" :
        $port =~ /^0\z|^[1-9][0-9]*\z/ ? int($port) :
        getservbyname($port, "udp") // die "Unknown UDP service '$port'\n";
    die "Port '$port' is out of range" if $port >= 2**16;
    return pack_sockaddr_in($port, $addr);
}

sub message_type {
    my ($type) = @_;

    return $message_type{$type} || "MESSAGE(uknown type $type)";
}

sub options_build {
    my (%options) = @_;

    # Make sure message_type exists and becomes the very first option
    my $type = delete $options{message_type} //
        die "Assertion: Missing message_type";
    my @names = ("message_type", sort keys %options);
    $options{message_type} = $type;
    my $str = "";
    for my $name (@names) {
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
                length $value == 4 || croak sprintf("Invalid IPv4 address size (length %d)", length $value);
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
        die "Option '$name': $@" if $@;
    }
    return $str . pack("W", OPTION_END);
}

sub fou {
    my ($fou, $ttl, $from, $to, $txt) = @_;

    my ($fou_port, $fou_addr) = unpack_sockaddr_in($fou);
    my $fou_ip   = inet_ntoa($fou_addr);

    socket(my $sender, PF_INET, SOCK_DGRAM, PROTO_UDP) ||
        die "Could not create socket: $^E";
    connect($sender, $fou) or die "Could not connect to $fou_ip:$fou_port: $^E";

    my ($dprt, $dst) = unpack_sockaddr_in($to);
    my ($sprt, $src) = unpack_sockaddr_in($from);

    my $packet_id = int rand 2**16;
    my $flags = $DF;

    my $length = length $txt;
    my $new_length = $length + $IHL * 4 + $UDP_HEADER;
    die "Packet too long" if $new_length >= 2**16;

    my $header = pack("CCnnnCCx2a4a4",
                      $IP_VERSION << 4 | $IHL,
                      0,
                      $new_length,
                      $packet_id,
                      $DF << 13 | 0,
                      # Avoid real outgoing packet if we are sending to 0.X.X.X
                      $ttl // ($dst =~ /^\0/ ? $TTL_LOW : $TTL),
                      PROTO_UDP,
                      $src,
                      $dst,
                  );
    my $sum = unpack("%32n*", $header);
    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    substr($header, 10, 2, pack("n", 0xffff - $sum));

    my $pseudo10 = pack("a4a4xC", $src, $dst, PROTO_UDP);
    my $udp_header = pack("nnn", $sprt, $dprt, $length + $UDP_HEADER);
    $txt .= "\0";

    $sum = unpack("%32n*", $pseudo10) + unpack("%32n*", $udp_header) + unpack("%32n*", $txt) + $length + $UDP_HEADER;

    while ($sum > 0xffff) {
        my $carry = $sum >> 16;
        $sum &= 0xffff;
        $sum += $carry;
    }
    chop $txt;
    my $buffer = $header . $udp_header . pack("n", 0xffff - $sum || 0xffff) . $txt;

    if ($verbose >= 3) {
        my $buf = $buffer;
        my ($ihl, $ecn, $length, $packet_id, $fragment, $ttl, $proto, $chksum, $src, $dst) = unpack("CCnnnCCna4a4", $buf);
        my $version = $ihl >> 4;
        $ihl &= 0xf;
        my $flags = $fragment >> 13;
        $fragment &= 0x1fff;
        # only TCP4
        $version == $IP_VERSION || die "Wrong version $version";
        # Only UDP
        $proto == PROTO_UDP || die "Wrong proto $proto";
        # Sanity check on buffer
        length($buf) == $length || die "Wrong length ", length($buf);
        # We don't handle IP options (yet)
        $ihl == $IHL || die "Wrong ihl $ihl";
        # Too many hops
        $ttl || die "Bad TTL $ttl";
        # Don't handle fragments (fragment offset)
        die "Unexpected fragment $fragment" if $fragment;
        # Don't handle fragments (MF flag set)
        die "Bad flags $flags" if $flags & 0x1;

        my $pseudo10 = pack("a4a4xC", $src, $dst, $proto);

        $ihl *= 4;
        my $header = substr($buf, 0, $ihl, "");
        $length -= $ihl;

        # No buffer padding needed since length($header) is even
        my $sum = unpack("%32n*", $header);
        # We (currently) don't check the header chksum since we assume we only
        # handle local packets which cannot fail
        while ($sum > 0xffff) {
            my $carry = $sum >> 16;
            $sum &= 0xffff;
            $sum += $carry;
        }
        $sum == 0xffff || die "Bad IP checksum $sum";

        $src = inet_ntoa($src);
        $dst = inet_ntoa($dst);

        my $dscp = $ecn >> 3;
        $ecn &= 0x7;
        print "HEADER: DSCP=$dscp, ECN=$ecn, ID=$packet_id, FLAGS=$flags, FRAGMENT=$fragment, TTL=$ttl, CHKSUM=$chksum, SUM=$sum, SRC=$src, DST=$dst\n";

        # Must have space for UDP header
        die "Bad UDP length $length" if $length < $UDP_HEADER;

        # Pad buffer 0 so a last single byte still gets processed as "n"
        $sum = unpack("%32n*", $buf . "\x0") + unpack("%32n*", $pseudo10) + $length;
        my ($sprt, $dprt, $udp_len, $udp_chksum) = unpack("nnnn", substr($buf, 0, $UDP_HEADER, ""));
        $udp_len == $length || die "Inconsistent UDP length";
        $length -= $UDP_HEADER;

        if ($udp_chksum) {
            while ($sum > 0xffff) {
                my $carry = $sum >> 16;
                $sum &= 0xffff;
                $sum += $carry;
            }
            $sum == 0xffff || die "Bad UDP chksum $sum";
        }

        print("SPRT=$sprt, DPRT=$dprt, LEN=$udp_len, CHK=$udp_chksum\n" .
              "Encapsulated FOU packet from $src:$sprt to $dst:$dprt\n");
    }
    my $rc = syswrite($sender, $buffer) //
        die "Could not send message: $^E";
    length $buffer == $rc ||
        die "Sent truncated FOU DHCP message\n";
}

sub packet_send {
    my ($type, $fou, $interface, $to, $ttl, $xid, $gateway_ip, $mac,
        $broadcast, $unicast, %options) = @_;

    croak "Missing mandatory option 'request_ip'" if
        !defined $options{request_ip} &&
        ($type == INFORM || $type == RELEASE || $type == DECLINE);
    my $ciaddr = exists $options{request_ip} ?
        inet_aton($options{request_ip}) || croak "Invalid 'request_ip' value" :
        INADDR_ANY;
    socket(my $sender, PF_INET, SOCK_DGRAM, PROTO_UDP) ||
        die "Could not create socket: $^E";
    !$broadcast || setsockopt($sender, SOL_SOCKET, SO_BROADCAST, 1) ||
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
    # my $from = pack_sockaddr_in(0, inet_aton("192.168.59.142"));
    #bind($sender, $from) or die "Could not bind: $^E";
    connect($sender, $to) or die "Could not connect: $^E";
    my $from = getsockname($sender) // die "Could not getsockname: $^E";
    my ($fport, $from_addr) = unpack_sockaddr_in($from);
    my $from_ip = inet_ntoa($from_addr);
    $gateway_ip = $from_ip if defined $gateway_ip && $gateway_ip eq "";
    if (!$mac) {
        $if //= IO::Interface::Simple->new_from_address($from_ip) //
            die "Could not get local interface for IP $from_ip";
        $mac = $if->hwaddr //
            croak "Could not get MAC address from interface address $from_ip";
        $mac =~ /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}\z/i ||
            die "Assertion: Invalid MAC address '$mac'";
        $mac =~ tr/://d;
        $mac = pack("H*", $mac);
    }

    my $buffer = pack("W4Nnna4x4x4a4a16x192N",
		      BOOTREQUEST, # Message opcode
		      HW_ETHERNET, # Hardware type
		      6,           # Hardware addr length (6 bytes) <= 16
		      0,           # Max Hops
		      $xid,
		      0,           # secs
                      $unicast ? 0 : FLAG_BROADCAST,	# flags
                      # No ciaddr for INFORM is against the RFC, but otherwise
                      # the gateway is ignored and sent to $ciaddr
                      # (with the ISC DHCP server, other servers may differ)
                      $type == DISCOVER || $type == DECLINE || $type == INFORM && $gateway_ip ? INADDR_ANY : $ciaddr,
                      # $type == DISCOVER || $type == DECLINE ? INADDR_ANY : $ciaddr,
                      $gateway_ip ? inet_aton($gateway_ip) // die("Could nor resolve gatway IP '$gateway_ip'"): INADDR_ANY,
                      $mac,
                      COOKIE,
                  );

    delete $options{request_ip} if
        $type == INFORM || $type == RELEASE;
    # Probably should add a check for overlong packets...
    $buffer .= options_build(size_max => 0xffff,
                             %options,
                             message_type => $type);
    if ($fou) {
        fou($fou, $ttl, $gateway_ip ? pack_sockaddr_in(BOOTPS, inet_aton($gateway_ip)) : pack_sockaddr_in(BOOTPC, inet_aton("0.0.0.1")), $to, $buffer);
    } else {
        !defined $ttl || setsockopt($sender, IPPROTO_IP, IP_TTL, int($ttl)) ||
            die "Could not set TTL: $^E";
        my $rc = syswrite($sender, $buffer) //
            die "Could not send message: $^E";
        length $buffer == $rc ||
            die "Sent truncated DHCP message\n";
    }
    if ($verbose >= 2) {
        my ($port, $addr) = unpack_sockaddr_in($to);
        printf("%s\nDHCP%s sent to %s:%d\n",
               $separator, message_type($type), inet_ntoa($addr), $port);
    }
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
            if ($verbose >= 2 && $disply_name ne "") {
                printf("%s:%s\t%s\n", $disply_name,
                       length $disply_name <= 6 ? "\t" : "",
                       ref $options->{$name} eq "ARRAY" ?
                       join(", ", map string_from_value($_), @{$options->{$name}}) :
                       string_from_value($options->{$name}));
            }
        } else {
            printf "Option %s: %s\n", $tag, string_from_value($value) if $verbose >= 2;
        }
    }
}

sub packet_receive {
    my ($socket, $timeout, $xid, $expect_addr, $mac) = @_;

    my $read_mask  = "";
    my $fd = fileno($socket) // die "Not a file descriptor";
    vec($read_mask, $fd, 1) = 1;
    my $now = clock_gettime(CLOCK_MONOTONIC);
    my $target_time = $now + $timeout;

    while (1) {
        $timeout = $target_time - $now;
        $timeout = 0 if $timeout < 0;
        my $rc = select(my $r = $read_mask, undef, undef, $timeout);
        if ($rc <= 0) {
            return undef if $rc == 0;
            next if $! == EINTR;
            die "Select failed: $^E";
        }

        my $server = recv($socket, my $buffer, BLOCK_SIZE, 0) //
            die "Could not recv: $^E";
        my ($server_port, $server_addr) = unpack_sockaddr_in($server) or
            die "Could not decode UDP sender address";
        my $server_ip = inet_ntoa($server_addr);
        print "Received packet from $server_ip:$server_port\n" if $verbose >= 3;
        if (ord $buffer == ($IP_VERSION << 4 | $IHL)) {
            # May be FOU encapsulated packet
            next if length $buffer < 20;
            my ($ihl, $ecn, $length, $id, $fragment, $ttl, $proto, $chksum, $src, $dst) = unpack("CCnnnCCna4a4", $buffer);
            printf("TEMP: IHL=%d, ECN=%d, LEN=%d, ID=%d, FRAGMENT=%d, TTL=%d, PROTO=%d, CHK=%04x, SRC=%s, DST=%s\n",
                   $ihl, $ecn, $length, $id, $fragment, $ttl, $proto, $chksum,
                   inet_ntoa($src), inet_ntoa($dst)) if $verbose >= 3;

            # Skip spammy multicast stuff
            next if MULTICAST_BEGIN le $dst && $dst lt MULTICAST_END;

            my $version = $ihl >> 4;
            $ihl &= 0xf;
            my $flags = $fragment >> 13;
            $fragment &= 0x1fff;
            # only TCP4
            $version == $IP_VERSION || next;
            # Only UDP
            $proto == PROTO_UDP || next;
            # Sanity check on buffer
            length($buffer) == $length || next;
            # We don't handle IP options (yet)
            $ihl == $IHL || next;
            # Too many hops. If 0 the packet shouldn't have been send anyways
            $ttl || next;
            # Don't handle fragments (fragment offset)
            next if $fragment;
            # Don't handle fragments (MF flag set)
            next if $flags & 0x1;

            my $pseudo10 = pack("a4a4xC", $src, $dst, $proto);

            $ihl *= 4;
            my $header = substr($buffer, 0, $ihl, "");
            $length -= $ihl;

            # No buffer padding needed since length($header) is even
            my $sum = unpack("%32n*", $header);
            while ($sum > 0xffff) {
                my $carry = $sum >> 16;
                $sum &= 0xffff;
                $sum += $carry;
            }
            $sum == 0xffff || next;

            print "Sender $server_ip:$server_port\n" if $verbose >= 3;

            $src = inet_ntoa($src);
            $dst = inet_ntoa($dst);

            my $dscp = $ecn >> 3;
            $ecn &= 0x7;
            print "HEADER: DSCP=$dscp, ECN=$ecn, ID=$id, FLAGS=$flags, FRAGMENT=$fragment, TTL=$ttl, CHKSUM=$chksum, SRC=$src, DST=$dst\n" if $verbose >= 3;

            # Must have space for UDP header
            next if $length < $UDP_HEADER;

            # Pad buffer 0 so a last single byte still gets processed as "n"
            $sum = unpack("%32n*", $buffer . "\x0") + unpack("%32n*", $pseudo10) + $length;
            my ($sprt, $dprt, $udp_len, $udp_chksum) = unpack("nnnn", substr($buffer, 0, $UDP_HEADER, ""));
            $udp_len == $length || die "Inconsistent UDP length";
            $length -= $UDP_HEADER;

            if ($udp_chksum) {
                while ($sum > 0xffff) {
                    my $carry = $sum >> 16;
                    $sum &= 0xffff;
                    $sum += $carry;
                }
                $sum == 0xffff || next;
            }

            $server_ip = $src;
            $server_addr = inet_aton($src);
            $server_port = $sprt;
            print "Decapsulated FOU packet from $src:$sprt to $dst:$dprt, LEN=$udp_len\n" if $verbose >= 2;
        }

        $server_port == BOOTPS || next;
        my ($op, $hw_type, $hw_len, $hops,
            $reply_xid, $secs, $flags,
            $client_addr, $your_addr, $boot_addr, $gateway_addr,
            $hw_addr,
            $server_name, $boot_file,
            $cookie, $options)
            = unpack("W4Nnna4a4a4a4a16a64a128Na*", $buffer);

        # Not BOOTREPLY happens. We will at least see our own broadcast
        $op == BOOTREPLY || next;
        $cookie && $cookie == COOKIE || next;
        $hw_addr = substr($hw_addr, 0, $hw_len);
        $hw_addr eq $mac || next;
        my $hw = mac_string($hw_addr);
        printf("%s\nReply (length %d) from %s:%d for MAC %s\n",
               $separator, length $buffer, $server_ip, $server_port, $hw) if
                   $verbose >= 2;
        $hw_type == HW_ETHERNET || next;
        $reply_xid == $xid || next;
        !$expect_addr || $server_addr eq $expect_addr || next;
        my %option = (
            server_packed => pack_sockaddr_in($server_port, $server_addr),
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
            hw		=> $hw,
        );
        defined $options || die "Truncated DHCP reply";
        print <<"EOF" if $verbose >= 2
op=$op, hw_type=$hw_type, hw_len=$hw_len, hops=$hops xid=$option{xid_ip} secs=$secs, flags=$flags
client IP:\t$option{client_ip}
Your   IP:\t$option{your_ip}
Server IP:\t$option{server_ip}
Gate   IP:\t$option{gateway_ip}
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
            printf("Server Name:\t%s\n",
                   string_from_value($option{server_name})) if
                       $verbose >= 2 && $option{server_name} ne "";
        }
        if ($boot_file) {
            $option{boot_file} = unpack("Z*", $boot_file);
            printf("Boot File:\t%s\n", string_from_value($option{boot_file})) if
                $verbose >= 2 && $option{boot_file} ne "";
        }
        exists $option{message_type} || die "No reply message type";
        if (exists $option{server}) {
            $option{server} eq $server_addr ||
                die sprintf("Inconsistent server: Received packet from %s but server identifier in packet is %s", $server_ip, inet_ntoa($option{server}));
        } elsif ($option{message_type} == NAK) {
            $option{server} = $server_addr;
        } else {
            die "Missing server identifier in DHCP reply";
        }

        # On my net the router can send a NAK even though the router does
        # not mot match the server identifier. So we should do a perl "next" if
        # server identifier does not match request

        return \%option;
    } continue {
        $now = clock_gettime(CLOCK_MONOTONIC);
    }
}

1;
