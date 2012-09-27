#!/usr/bin/perl

use Net::PcapWriter;
use strict;

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

sub makeiptpheaders {
		my ($src_host,$src_port,$dst_host,$dst_port,$leng,$netp, $flagsref, $payload) = @_;
		my $zero_cksum = 0;
		# Lets construct the TCP half
		my $ip_proto           = $netp;
		my $tcp_len            = 20;
		my $syn                = 13456;
		my $ack                = 0;
		my $tcp_headerlen      = "5";
		my $tcp_reserved       = 0;
		my $tcp_head_reserved  = $tcp_headerlen .
				$tcp_reserved;
		my $null               = 0;
		my $tcp_win            = 124;
		my $tcp_urg_ptr        = 0;

		my ($tcp_urg, $tcp_ack, $tcp_psh, $tcp_rst, $tcp_syn, $tcp_fin) = tcp_flags(@$flagsref);
		my $tcp_all = $null . $null .
				$tcp_urg . $tcp_ack .
				$tcp_psh . $tcp_rst .
				$tcp_syn . $tcp_fin ;

		# In order to calculate the TCP checksum we have
		# to create a fake tcp header, hence why we did
		# all this stuff :) Stevens called it psuedo headers :)

		my ($tcp_pseudo) = pack('a4a4CCnnnNNH2B8nvn',
														$tcp_len,$src_port,$dst_port,$syn,$ack,
														$tcp_head_reserved,$tcp_all,$tcp_win,$null,$tcp_urg_ptr);

		my $cksum = $null;
		my $udp_pseudo = pack("nnnna*", $src_port,$dst_port,$leng-20, $cksum, $payload);

		my ($tcp_checksum) = &checksum($tcp_pseudo);
		my ($udp_checksum) = &checksum($udp_pseudo);
		my $hdrlen = tpheader_length($netp);
		my $totlen=$leng+$hdrlen;
		# Now lets construct the IP packet
		my $ip_ver             = 4;
		my $ip_len             = 5;
		my $ip_ver_len         = $ip_ver . $ip_len;
		my $ip_tos             = 00;
		my ($ip_tot_len)       = $totlen + 20;
		my $ip_frag_id         = 19245;
		my $ip_frag_flag       = "010";
		my $ip_frag_oset       = "0000000000000";
		my $ip_fl_fr           = $ip_frag_flag . $ip_frag_oset;
		my $ip_ttl             = 30;
		my ($pkt);

		my $ip_pseudo = pack('H2H2n' .
												 'nB16C2' .
												 'a4a4',
												 $ip_ver_len, $ip_tos, $ip_tot_len,
												 $ip_frag_id, $ip_fl_fr, $ip_ttl, $netp,
												 $src_host, $dst_host);
		my $ip_cksum = checksum($ip_pseudo);

		my $iphdr = pack('H2H2nnB16C2Sa4a4',
										 $ip_ver_len,$ip_tos,$ip_tot_len,$ip_frag_id,
										 $ip_fl_fr,$ip_ttl,$netp,$ip_cksum,$src_host,
										 $dst_host);

		# Lets pack this baby and ship it on out!
		if($netp==6){
				$pkt = $iphdr . pack('nnNNH2B8nvna*',
										$src_port,$dst_port,$syn,$ack,$tcp_head_reserved,
										$tcp_all,$tcp_win,$tcp_checksum,$tcp_urg_ptr,$payload);
		} elsif($netp==17){
				$pkt = $iphdr . pack('nnnna*',
														 $src_port,$dst_port,$leng, $cksum, $payload);

		} else {
				print "WTF?. not supported protocol \n";
		}

		return $pkt;
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
