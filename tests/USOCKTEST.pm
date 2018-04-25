package USOCKTEST;
use strict;
use warnings;
use Exporter;

use File::Temp qw(tempfile);

our @ISA        = qw(Exporter);
our @EXPORT     = qw(usock_src_serv);

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
my $i;
my $len;
my @args;
my @fstats;

sub usock_src_serv
{
	my $test_name	= 'UNIX DGRAM SOCK SRC SERVER';
	my $sockfile	= '/tmp/usock_test';
	my $n_bytes	= 672;
	my $ret		= 1;
	my $pid;

	-e $sockfile && unlink $sockfile;

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($out_fh, $out_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);

	$ofh = select($out_fh);
        $| = 1;
        select($ofh);

	print $cfg_fh "{\niotype: UNIX_SOCK; dir: src; ",
	"conn: server; sockpath: /tmp/usock_test;\n",
	"(iotype: FILE; path: $out_file;)\n}\n";

	close $cfg_fh;

	$ret = fork_exec(\$cfg_file) || print "Error exec'ing ioproxyd";

        if (check_io($test_name, $n_bytes)) {
                print "$test_name 1: PASS\n";
        } else {
                $ret = 0;
                printf "$test_name 1: FAIL\n";
        }

	$pid = `/usr/bin/pgrep ioproxyd`;
	kill 'HUP', $pid;
	sleep 5;


        if (check_io($test_name, $n_bytes * 2)) {
                print "$test_name 2: PASS\n";
        } else {
                $ret = 0;
                printf "$test_name 2: FAIL\n";
        }

	return $ret;
}

sub check_io
{
	my $test	= shift;
	my $bytes	= shift;
	my $len		= 0;
	my $ret;

	while ($len < $bytes) {
            @fstats = stat($out_fh);
            $len = $fstats[7];
	    print "Sleeping...while waiting for I/O to complete\n";
            sleep(1);
        }

        if ($fstats[7] == $bytes) {
            print "$test: \tPASS (Input len: $bytes fsz: $fstats[7])\n";
            return 1;
        } else {
            print "$test: \tFAIL: Input len: $bytes fsz: $fstats[7])\n";
            return 0;
        }
}

sub fork_exec
{
	my $file = shift;
	my @args;
 	my $pid; 

	push @args, $$file;

	$pid = fork;
	if ($pid == 0) {
	    close $out_fh;
	    exec($IOPROXY, "-f", @args) || die "exec failed: $!\n";
	    exit(0);
	} else {
	    return 1;
	}
}

1;
