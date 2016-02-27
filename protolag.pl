#!/usr/bin/perl -w

# protolag.pl
# passive protocol latency
# sniff packets off the wire, keep track of sessions and measure latency with no active tests; report list of active connections and their respective lag; dsthost and protocol (ARP,ICMP,UDP port, TCP port; http etc)
#
# 2012-03-31 22:17:01 genesis; take windump/tcpdump as input; make sure to use -ttvvnn flags
# 2012-04-02 22:19:51 experimenting with Net::Pcap
#		need to maintain watching existing connections; track TCP acknowledgements; udp streams
use strict;
use Time::HiRes;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::ICMP;
use NetPacket::TCP;
use NetPacket::UDP;


#use threads;
# worker thread to do the sniffing, main thread to update the tk window

use Tk;


$| = 1;


my $err;

my @list = Net::Pcap::findalldevs(\$err);
for (my $i = 0; $i <= $#list; $i++) {
	print "$i. $list[$i]\n";
}
my $dev = $list[0];
#my $dev = Net::Pcap::lookupdev(\$err);
#if (defined $err) {
#    die 'Unable to determine network device for monitoring - ', $err;
#}

my ($address, $netmask);
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    warn 'Unable to look up device information for ', $dev, ' - ', $err;
}
printf("Sniffing interface %s/%s\n", join(".", unpack "C4", pack "N",$address), join(".", unpack "C4", pack "N",$netmask));

my $snaplen = 1500;
my $promisc = 0;
my $to_ms = -1;
my $object = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);

my %protocols = (
	'1' => 'icmp',
	'6' => 'tcp',
	'17' => 'udp'
);

my $data = {}; # session tracking


#Net::Pcap::loop($object, $count, \&callback_function, $user_data)
my $timer = time;
while (1) {
	Net::Pcap::dispatch($object, 0, \&process_packet, undef);

	Time::HiRes::sleep 0.01;
	if (time - $timer > 0) {
		#printf("### %d sessions being tracked ###\n", scalar keys %$data);
		$timer = time;
	}
}

exit;

# ==============================================================================

sub enumerate {
	my $hash = shift;
  while (my ($name,$value) = each %$hash) {
  	$value = "" unless (defined $value);
  	$value =~ s/[^\w|\.]/_/g;
  	print "$name=$value, ";
  }
}

sub process_packet {
	my ($user_data, $header, $packet) = @_;
	my $ether_data = NetPacket::Ethernet::strip($packet);
  my $ip = NetPacket::IP->decode($ether_data);
  my $proto = $protocols{$ip->{'proto'}} || "unknown";
  my $icmp = NetPacket::ICMP->decode($ip->{'data'});
  my $tcp = NetPacket::TCP->decode($ip->{'data'}) if ($proto eq "tcp" );
  my $udp = NetPacket::UDP->decode($ip->{'data'});

  #print $ip->{'src_ip'}, ":", " -> ", $ip->{'dest_ip'}, "\n";

	my $stamp = $header->{'tv_sec'} + ($header->{'tv_usec'}/1000000);
	
	my $srcport = my $destport = my $flags = "";
	if ($proto eq "tcp" ) {
		$srcport = $tcp->{'src_port'};
		$destport = $tcp->{'dest_port'};
		$flags = $tcp->{'flags'};
	} elsif ($proto eq "udp") {
		$srcport = $udp->{'src_port'};
		$destport = $udp->{'dest_port'};
	} elsif ($proto eq "icmp") {
		$srcport = $icmp->{'type'};
		#enumerate($icmp); print "\n";
	}
	#print "*** $stamp $proto $ip->{src_ip}:$srcport -> $ip->{dest_ip}:$destport $flags\n";

	# if TCP SYN, begin session tracking
	if ($flags eq "2") { # SYN
		my $session = sprintf("tcp_%s_%d_%s_%d", $ip->{'src_ip'}, $srcport, $ip->{'dest_ip'}, $destport);
		$data->{$session}{'syn'} = $stamp;
	}
	if ($flags eq "24") { # SYN-ACK
		my $session = sprintf("tcp_%s_%d_%s_%d", $ip->{'dest_ip'}, $destport, $ip->{'src_ip'}, $srcport);
		if (exists $data->{$session}) {
			my $diff = $stamp - ($data->{$session}{'syn'} || 0);
			printf(" TCP %47s latency: %4d ms (syn-ack)\n", $session, $diff * 1000);
			delete $data->{$session};
		}
	}

	# ICMP echo/reply latency
	if ($proto eq "udp") {
		my $session = sprintf("udp_%s_%d_%s_%d", $ip->{'dest_ip'}, $destport, $ip->{'src_ip'}, $srcport);
		if (exists $data->{$session}) {
			my $diff = $stamp - ($data->{$session}{'a'} || 0);
			printf(" UDP %47s latency: %4d ms\n", $session, $diff * 1000);
			delete $data->{$session};
		} else {
			$session = sprintf("udp_%s_%d_%s_%d", $ip->{'src_ip'}, $srcport, $ip->{'dest_ip'}, $destport);
			$data->{$session}{'a'} = $stamp;
		}
	}
	
	# ICMP echo/reply latency
	if ($proto eq "icmp" and $icmp->{'type'} == 0) { # echo reply
		my $session = sprintf("icmp_%s_%s", $ip->{'dest_ip'}, $ip->{'src_ip'});
		if (exists $data->{$session}) {
			my $diff = $stamp - ($data->{$session}{'echo'} || 0);
			printf("ICMP %47s latency: %4d ms\n", $session, $diff * 1000);
			delete $data->{$session};
		}
	} elsif ($proto eq "icmp" and $icmp->{'type'} == 8) { # echo request
		my $session = sprintf("icmp_%s_%s", $ip->{'src_ip'}, $ip->{'dest_ip'});
		$data->{$session}{'echo'} = $stamp;
	}
	#enumerate($header);
	#print "[IP] ";
  #enumerate($ip);
  #print "\n\n";
  #print "[ICMP] ";
  #enumerate($icmp);
  #print "\n\n";
  #print "[TCP] ";
  #enumerate($tcp);
  #print "\n\n";
  #print "[UDP] ";
  #enumerate($udp);
  #print "\n\n";
  #print "=" x 40, "\n";

}
