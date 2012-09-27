#!/usr/bin/perl

use Net::PcapWriter;
use strict;
use warnings;

my  ($FINname, $FOUTname, $npkts);
my ($line,$tv,$proto,$netsrc,$tpsrc, $netdst,$tpdst,$approto, $netlen, $payload, $flags, $data, $datarand);
my ($sec,$mu,$basename,$FOUT2name);

$basename= "test";
$FINname  = $ARGV[0] || "$basename.txt";					#Just a string to identify this experiment.
$FOUTname = $ARGV[1] || "$basename.pcap";
$FOUT2name = $ARGV[2] || "$basename.cap";
$npkts    =  $ARGV[3] || "-1";

my $writer = Net::PcapWriter->new($FOUTname) or die "Cant open $FOUTname $!.";
open(FIN, "$FINname") or die "Cant open $FINname, $!.";

$datarand=&generate_random_string(67000);

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
				print "Not tcp or udp.\n";
				next;
    }

    my @flags = split(/,/, $flags);
    my $src_host=(gethostbyname($netsrc))[4];
    my $dst_host=(gethostbyname($netdst))[4];
		my $hdrlen = tpheader_length($proto);

    $dlen=$netlen-length($payload);
    print "$proto $netsrc,$tpsrc, $netdst,$tpdst, $payload \t";

    $data=sprintf('%s%s',$payload,substr($datarand,0,$dlen));
    printf("size of data is %d with $dlen $netlen.\n",length($data));
    my ($packet) = makeiptpheaders($src_host, $tpsrc, $dst_host, $tpdst, $netlen, $proto, \@flags, $data);
    $writer->packet($packet,$tv);
}

printf("Doing: pcap2cap -m 'convert' -c 'Converted via txt2pcap, pcap2cap' -o $FOUT2name $FOUTname\n");
system("pcap2cap -m 'convert' -c 'Converted via txt2pcap, pcap2cap' -o $FOUT2name $FOUTname");

print "done";

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

		foreach ( @_ ){
				if ( $_ eq 'DATA' ){ next; }
				elsif ( $_ eq 'URG' ){ $urg = 1; }
				elsif ( $_ eq 'ACK' ){ $ack = 1; }
				elsif ( $_ eq 'PSH' ){ $psh = 1; }
				elsif ( $_ eq 'RST' ){ $rst = 1; }
				elsif ( $_ eq 'SYN' ){ $syn = 1; }
				elsif ( $_ eq 'FIN' ){ $fin = 1; }
				else { print "unknown TCP flag `$_', ignored\n"; }
		}

		return ($urg, $ack, $psh, $rst, $syn, $fin);
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

sub make_tcp_header {
		my ($ip, $src_port, $dst_port, $flagsref, $payload) = @_;
		my $iphdr = ip_pack($ip);

		# Lets construct the TCP half
		my $tcp_len            = 20;
		my $syn                = 13456;
		my $ack                = 0;
		my $tcp_headerlen      = "5";
		my $tcp_reserved       = 0;
		my $tcp_head_reserved  = $tcp_headerlen .
				$tcp_reserved;
		my $tcp_win            = 124;
		my $tcp_urg_ptr        = 0;

		my ($tcp_urg, $tcp_ack, $tcp_psh, $tcp_rst, $tcp_syn, $tcp_fin) = tcp_flags(@$flagsref);
		my $tcp_all = 0 . 0 .
				$tcp_urg . $tcp_ack .
				$tcp_psh . $tcp_rst .
				$tcp_syn . $tcp_fin ;

		# TCP fake header
		my ($tcp_pseudo) = pack('a4a4' .
														'CCn' .
														'nn' .
														'nn' .
														'H2B8nnna*',
														$ip->{ip_src}, $ip->{ip_dst},
														0, $ip->{ip_p}, $ip->{ip_len},
														$src_port,$dst_port,
														$syn,$ack,
														$tcp_head_reserved,$tcp_all,$tcp_win, 0, $tcp_urg_ptr, $payload);
		my ($tcp_checksum) = &checksum($tcp_pseudo);

		return $iphdr . pack('nnNNH2B8nSna*',
												 $src_port,$dst_port,$syn,$ack,$tcp_head_reserved,
												 $tcp_all,$tcp_win,$tcp_checksum,$tcp_urg_ptr,$payload);
}

sub make_udp_header {
		my ($ip, $src_port, $dst_port, $flagsref, $payload) = @_;
		my $iphdr = ip_pack($ip);

		my $udp_pseudo = pack('a4a4' .
													'CCn' .
													'nn' .
													'nna*',
													$ip->{ip_src}, $ip->{ip_dst},
													0, $ip->{ip_p}, $ip->{ip_len},
													$src_port, $dst_port,
													$ip->{ip_len}, 0, $payload);

		my ($udp_checksum) = &checksum($udp_pseudo);

		return $iphdr . pack('nnnSa*', $src_port, $dst_port, $ip->{ip_len}, $udp_checksum, $payload);
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

sub makeiptpheaders {
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

# Stolen from NetPacket
sub htons {
    my ($in) = @_;
    return(unpack('n*', pack('S*', $in)));
}
