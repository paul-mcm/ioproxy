package SOCKETTEST;
use strict;
use warnings;
use Exporter;

use PRIVATE;
use File::Temp qw(tempfile);

our @ISA        = qw(Exporter);
our @EXPORT     = qw(tls_serv tls_cli tcp_serv tcp_cli);

my $INPUT       = "a long string of text that has no meaning\n";
my $IOPROXY     = '../ioproxyd';
my $TEMPLATE    = 'ioproxyd.XXXX';
my $BUFCNT      = 64;

my $cfg_fh;
my $cfg_file;
my $out_fh;
my $out_file;
my $tmp_outfile;
my $in_fh;
my $tmp_infile;
my $ofh;
my $pid;
my $i;
my $len;
my @args;
my @fstats;

sub tls_serv
{

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($out_fh, $out_file) = tempfile($TEMPLATE, TMPDIR => 1);

	$ofh = select($out_fh);
        $| = 1;
        select($ofh);

	print $cfg_fh "{\niotype: TCP_SOCK; dir: src; port: 2345; ",
	"conn: server; tls: true;",
	"host_key: $HOST_KEY; ",
	"host_cert: $HOST_CERT;\n",
	"(iotype: FILE; path: $out_file;)\n}\n";

	close $cfg_fh;

	push @args, $cfg_file;

	$pid = fork;
	if ($pid == 0) {
	    close $out_fh;
	    exec($IOPROXY, "-f", @args) || die "exec failed: $!\n";
	    exit(0);
	}

	sleep(60);

}
#
#sub tls_cli
#{
#	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
#
#}
#
#sub tcp_serv
#{
#	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
#}
#
#sub tcp_cli
#{
#	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
#
#}
#

1;
