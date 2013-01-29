#!/usr/bin/perl

use Net::PcapWriter;
use POSIX;
use strict;
use warnings;

my ($FINname, $FOUTname, $npkts);
my ($line,$tv,$proto,$netsrc,$tpsrc, $netdst,$tpdst,$approto, $netlen, $payload, $flags, $data, $datarand);
my ($sec,$mu,$basename,$FOUT2name,$mampid,$comment);

$basename  = "test";
$FINname   = $ARGV[0] || "$basename.txt";					#Just a string to identify this experiment.
$FOUTname  = $ARGV[1] || "$basename.pcap";
$FOUT2name = $ARGV[2] || "$basename.cap";
$npkts     = $ARGV[3] || "-1";
$mampid    = $ARGV[4] || "convert";
$comment   = $ARGV[5] || "Converted via txt2pcap, pcap2cap";

my $writer = Net::PcapWriter->new($FOUTname) or die "Cant open $FOUTname $!.";
open(FIN, "$FINname") or die "Cant open $FINname, $!.";

$datarand=&generate_random_string(67000);

my $pkts=0;
my $dlen;
while($line=<FIN>){
	$line =~ s/^\s+//; # remove leading whitespace
	$line =~ s/\s+$//; # remove trailing whitespace

	# ignore comments and empty lines
	my $is_comment = $line =~ /#/;
	my $is_blank = length($line) == 0;
	if ( $is_comment || $is_blank ) {
		next;
	}

	($tv,$proto,$netsrc,$tpsrc, $netdst,$tpdst, $netlen, $flags, $payload) = split(/\s+/, $line, 9);
	if(!($proto=~/udp||tcp/)) {
		print "$0: warning: Not tcp or udp, ignored.\n";
		next;
	}

	# fix timestamp, pcapwriter gets it wrong
	my ($tsec, $tmsec);
	($tsec, $tmsec) = split(/\./, $tv);
	$tsec = int($tsec);
	$tmsec = int($tmsec);

	# if no payload was specifed create an empty one
	if ( !defined $payload ){
		$payload = '';
	}

	my @flags = split(/,/, $flags);
	my $src_host=(gethostbyname($netsrc))[4];
	my $dst_host=(gethostbyname($netdst))[4];
	my $hdrlen = tpheader_length($proto);

	$dlen=$netlen-length($payload);
	my @tmp = ($tsec,$tmsec);
	$data=sprintf('%s%s',$payload,substr($datarand,0,$dlen));
	my ($packet) = make_iptp_headers($src_host, $tpsrc, $dst_host, $tpdst, $netlen, $proto, \@flags, $data);
	$writer->packet($packet, \@tmp);

	$pkts++;
}

if ( $pkts == 0 ){
	print "No packets, ignored.\n";
	unlink($FOUTname);
	exit 1
}

my $command = "pcap2cap -qm '$mampid' -c '$comment' -o '$FOUT2name' '$FOUTname'";
print "$command\n";
system($command);

sub tpheader_length {
	my ($proto) = @_;
	if ( $proto == 6  ){ return 20; }
	if ( $proto == 17 ){ return 8;  }
	return 0; # will bail out later
}

sub generate_random_string
{
	my $length_of_randomstring=shift;# the length of
	# the random string to generate

	my @chars=('a'..'z','A'..'Z','0'..'9','_');
	my $random_string;
	foreach (1..$length_of_randomstring)
	{
		# rand @chars will generate a random
		# number between 0 and scalar @chars
		$random_string.=$chars[rand @chars];
	}
	return $random_string;
}

sub tcp_flags {
	# defaults
	my $urg = 0;
	my $ack = 0;
	my $psh = 0;
	my $rst = 0;
	my $syn = 0;
	my $fin = 0;
	my $offset = 0;

	foreach ( @_ ){
		if ( $_ eq 'DATA' ){ next; }
		elsif ( $_ eq 'URG' ){ $urg = 1; }
		elsif ( $_ eq 'ACK' ){ $ack = 1; }
		elsif ( $_ eq 'PSH' ){ $psh = 1; }
		elsif ( $_ eq 'RST' ){ $rst = 1; }
		elsif ( $_ eq 'SYN' ){ $syn = 1; }
		elsif ( $_ eq 'FIN' ){ $fin = 1; }
		elsif ( $_ =~ /OPT_NOP\((\d+)\)/ ){ $offset += $1; }
		else { print "unknown TCP flag `$_', ignored\n"; }
	}

	return ($urg, $ack, $psh, $rst, $syn, $fin, $offset);
}

sub ip_checksum {
	my ($ip) = @_;
	$ip->{ip_sum} = 0;
	return checksum(ip_pack($ip));
}

sub ip_pack {
	my ($ip) = @_;
	return pack('H2H2n' .
				'nB16' .
				'C2S' .
				'a4a4',
				$ip->{ip_v} . $ip->{ip_hl}, $ip->{ip_tos}, $ip->{ip_len} + 4 * $ip->{ip_hl},
				$ip->{ip_id}, $ip->{ip_off},
				$ip->{ip_ttl}, $ip->{ip_p}, $ip->{ip_sum},
				$ip->{ip_src}, $ip->{ip_dst});
}

sub tcp_checksum {
	my ($ip, $tcp, $payload) = @_;
	my $ip_pseudo = pack('a4a4CCn',
						 $ip->{ip_src}, $ip->{ip_dst},
						 0, $ip->{ip_p}, $ip->{ip_len});
	my $tcp_pseudo = tcp_pack($tcp, $payload);
	return checksum($ip_pseudo . $tcp_pseudo);
}

sub tcp_options {
	my ($n) = @_;
	my $nop = pack('C', 1);
	my $pad = pack('C', 0);

	$data = $nop x $n;
	while ( length($data) % 4 != 0 ){
		$data .= $pad;
	}

	return $data;
}

sub tcp_pack {
	my ($tcp, $payload) = @_;
	return pack('nnNNH2B8nSna*a*',
				$tcp->{src}, $tcp->{dst}, $tcp->{seq},$tcp->{ack_seq}, sprintf("%x0", $tcp->{doff}),
				$tcp->{flags}, $tcp->{window}, $tcp->{check}, $tcp->{urg_ptr}, $tcp->{options}, $payload);
}

sub make_tcp_header {
	my ($ip, $src_port, $dst_port, $flagsref, $payload) = @_;

	my ($tcp_urg, $tcp_ack, $tcp_psh, $tcp_rst, $tcp_syn, $tcp_fin, $options) = tcp_flags(@$flagsref);
	my $offset = POSIX::ceil($options / 4);
	my $tcp = {
		src => $src_port,
		dst => $dst_port,
		seq => 13456,
		ack_seq => 0,
		doff => (5 + $offset),
		flags => "00" . $tcp_urg . $tcp_ack . $tcp_psh . $tcp_rst .	$tcp_syn . $tcp_fin,
		window => 124,
		check => 0,
		urg_ptr => 0,
		options => tcp_options($options),
	};

	# hack to get right ip-len (size of tcp header changed with options)
	if ( $offset > 0 ){
		$ip->{ip_len} += $offset * 4;
		$ip->{ip_sum} = ip_checksum($ip);
	}

	$tcp->{check} = tcp_checksum($ip, $tcp, $payload);
	return ip_pack($ip) . tcp_pack($tcp, $payload);
}

sub udp_checksum {
	my ($ip, $udp, $payload) = @_;
	my $pseudo = pack('a4a4' .
					  'CCn' .
					  'nn' .
					  'nna*',
					  $ip->{ip_src}, $ip->{ip_dst},
					  0, $ip->{ip_p}, $ip->{ip_len},
					  $udp->{src}, $udp->{dst},
					  $udp->{len}, 0, $payload);
	return checksum($pseudo);
}

sub udp_pack {
	my ($udp, $payload) = @_;
	return pack('nnnSa*', $udp->{src}, $udp->{dst}, $udp->{len}, $udp->{sum}, $payload);
}

sub make_udp_header {
	my ($ip, $src_port, $dst_port, $flagsref, $payload) = @_;

	my $udp = {
		src => $src_port,
		dst => $dst_port,
		len => $ip->{ip_len},
		sum => 0,
	};
	$udp->{sum} = udp_checksum($ip, $udp, $payload);

	return ip_pack($ip) . udp_pack($udp, $payload);
}

sub make_tp_header {
	my $proto = $_[0]->{ip_p};
	if( $proto == 6 ){
		return make_tcp_header(@_);
	} elsif( $proto == 17 ){
		return make_udp_header(@_);
	} else {
		print "WTF?. not supported protocol \n";
	}
}

sub make_iptp_headers {
	my ($src_host,$src_port,$dst_host,$dst_port,$leng,$netp, $flagsref, $payload) = @_;

	my $ip = {
		ip_v => 4,
		ip_hl => 5,
		ip_tos => 00,
		ip_len => $leng + tpheader_length($netp),
		ip_id => 19245,
		ip_off => "010" . "0000000000000",
		ip_ttl => 30,
		ip_p => $netp,
		ip_sum => 0,
		ip_src => $src_host,
		ip_dst => $dst_host,
	};
	$ip->{ip_sum} = ip_checksum($ip);

	return make_tp_header($ip, $src_port, $dst_port, $flagsref, $payload);
}

sub checksum {
	# This of course is a blatent rip from _the_ GOD,
	# W. Richard Stevens.

	my ($msg) = @_;
	my ($len_msg,$num_short,$short,$chk);
	$len_msg = length($msg);
	$num_short = $len_msg / 2;
	$chk = 0;
	foreach $short (unpack("S$num_short", $msg)) {
		$chk += $short;
	}
	$chk += unpack("C", substr($msg, $len_msg - 1, 1)) if $len_msg % 2;
	$chk = ($chk >> 16) + ($chk & 0xffff);
	return(~(($chk >> 16) + $chk) & 0xffff);
}
