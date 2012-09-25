#!/usr/bin/perl

use Net::PcapWriter;
use Time::HiRes qw (gettimeofday);
use strict;

my  ($FINname, $FOUTname, $npkts);
my ($line,$tv,$proto,$netsrc,$tpsrc, $netdst,$tpdst,$approto, $netlen, $payload, $data,$datarand);
my ($sec,$mu,$hdrlen,$basename,$FOUT2name);

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
    if($line =~ /#/) {
				next;
    }
    
    ($tv,$proto,$netsrc,$tpsrc, $netdst,$tpdst, $netlen, $payload) = split(/\s+/, $line, 7);
    if(!($proto=~/udp||tcp/)) {
				print "Not tcp or udp.\n";
				next;
    }

    my $src_host=(gethostbyname($netsrc))[4];
    my $dst_host=(gethostbyname($netdst))[4];

    if($proto==6){
				$hdrlen=20;
    }
    if($proto==17){
				$hdrlen=8;
    }
		
    $dlen=$netlen-length($payload)-$hdrlen-34;
    print "$proto $netsrc,$tpsrc, $netdst,$tpdst, $payload \t";
    
    $data=sprintf('%s%s',$payload,substr($datarand,0,$dlen));
    printf("size of data is %d with $dlen $netlen.\n",length($data));
    my ($packet) = makeiptpheaders($src_host, $tpsrc, $dst_host, $tpdst,$dlen,$proto,$data);
    $writer->packet($packet,$tv);
}

printf("Doing: pcap2cap -m 'convert' -c 'Converted via txt2pcap, pcap2cap' -o $FOUT2name $FOUTname\n");
system("pcap2cap -m 'convert' -c 'Converted via txt2pcap, pcap2cap' -o $FOUT2name $FOUTname");

print "done";

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


sub makeiptpheaders {
		my ($src_host,$src_port,$dst_host,$dst_port,$leng,$netp,$payload) = @_;
		my $zero_cksum = 0;
		# Lets construct the TCP half
		my $ip_proto          = $netp;
		my ($tcp_len)          = 20;
		my $syn                = 13456;
		my $ack                = 0;
		my $tcp_headerlen      = "5";
		my $tcp_reserved       = 0;
		my $tcp_head_reserved  = $tcp_headerlen .
				$tcp_reserved;
		my $tcp_urg            = 0; # Flag bits
		my $tcp_ack            = 0; # eh no
		my $tcp_psh            = 0; # eh no
		my $tcp_rst            = 0; # eh no
		my $tcp_syn            = 1; # yeah lets make a connexion! :)
		my $tcp_fin            = 0;
		my $null               = 0;
		my $tcp_win            = 124;
		my $tcp_urg_ptr        = 0;
		my $tcp_all            = $null . $null .
				$tcp_urg . $tcp_ack .
				$tcp_psh . $tcp_rst .
				$tcp_syn . $tcp_fin ;



		# In order to calculate the TCP checksum we have
		# to create a fake tcp header, hence why we did
		# all this stuff :) Stevens called it psuedo headers :)

		my ($tcp_pseudo) = pack('a4a4CCnnnNNH2B8nvn',
														$tcp_len,$src_port,$dst_port,$syn,$ack,
														$tcp_head_reserved,$tcp_all,$tcp_win,$null,$tcp_urg_ptr);

		my $cksum;
		my $udp_pseudo = pack("nnnna*", $src_port,$dst_port,$leng-20, $cksum, $payload);


		my ($tcp_checksum) = &checksum($tcp_pseudo);
		my ($udp_checksum) = &checksum($udp_pseudo);
		my $hdrlen;
		if($netp==6){
				$hdrlen=20;
		}
		if($netp==17){
				$hdrlen=8;
		}
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
		# Lets pack this baby and ship it on out!
		if($netp==6){
				$pkt = pack('H2H2nnB16C2na4a4nnNNH2B8nvna*',
										$ip_ver_len,$ip_tos,$ip_tot_len,$ip_frag_id,
										$ip_fl_fr,$ip_ttl,$netp,$zero_cksum,$src_host,
										$dst_host,$src_port,$dst_port,$syn,$ack,$tcp_head_reserved,
										$tcp_all,$tcp_win,$tcp_checksum,$tcp_urg_ptr,$payload);
		} elsif($netp==17){
				$pkt = pack('H2H2nnB16C2na4a4nnnna*',
										$ip_ver_len,$ip_tos,$ip_tot_len,$ip_frag_id,
										$ip_fl_fr,$ip_ttl,$netp,$zero_cksum,$src_host,
										$dst_host,$src_port,$dst_port,$leng, $cksum, $payload); 

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
