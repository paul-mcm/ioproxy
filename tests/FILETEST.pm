package FILETEST;
use strict;
use warnings;
use Exporter;

use File::Temp qw(tempfile);
use Fork;

our @ISA        = qw(Exporter);
our @EXPORT     = qw(file_test);

my $INPUT       = "a long string of text that has no meaning\n";
my $IOPROXY     = '../ioproxyd';
my $TEMPLATE    = 'ioproxyd.XXXX';
my $BUFCNT      = 64;

my $cfg_fh;
my $cfg_file;
my $out_fh;
my $tmp_outfile;
my $in_fh;
my $tmp_infile;
my $ofh;
my $pid;
my $ret;
my $i;
my $len;
my @forkargs;
my @fstats;

sub file_test
{	
	$pid = -1;
	$len = 0;
	$ret = 1;

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($in_fh, $tmp_infile) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($out_fh, $tmp_outfile) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);

	$ofh = select($in_fh);
	$| = 1;
	select($ofh);

	print $cfg_fh "{\niotype: FILE; dir: src; path: $tmp_infile;\n", 
	"(iotype: FILE; path: $tmp_outfile;)\n}";

	close $cfg_fh;

	push @forkargs, $IOPROXY;
        push @forkargs, "-f";
        push @forkargs, $cfg_file;
	fork_exec(\@forkargs) || die "Error exec'ing ioproxyd";

	sleep(3);
	if (do_io()) {
		print "FILE TEST 1: PASS\n";
	} else {
		$ret = 0;
		printf "FILE TEST 1: FAIL\n";
	}

	$pid = `/usr/bin/pgrep ioproxyd`;
	kill 'HUP', $pid;

	sleep(3);

	if (do_io()) {
		print "FILE TEST 2: PASS\n";
	} else {
		$ret = 0;
		printf "FILE TEST 2: FAIL\n";
	}

	$pid = `/usr/bin/pgrep ioproxyd`;
	kill 'TERM', $pid;
	close $in_fh;
	unlink $in_fh;
	close $out_fh;
	unlink $out_fh;
	unlink $cfg_fh;
	
	return $ret;
}

sub do_io
{
	for ($i = 0; $i < $BUFCNT; $i++) {
	    print $in_fh "$INPUT" || die "print failed: $!\n";
	}

	while ($len < length($INPUT) * $BUFCNT) {
	    @fstats = stat($out_fh);
	    $len = $fstats[7];
	    sleep(1);
	}

	if ((length($INPUT) * $BUFCNT) == $fstats[7]) {
	    print "FILE TEST: \tPASS (Input: " . (length($INPUT) * $BUFCNT) . " fsz: $fstats[7])\n";
	    return 1;
        } else {
            print "FILE TEST: \tFAIL: Input len: " . (length($INPUT) * $BUFCNT) . "fsz: $fstats[7])\n";
            return 0;
        }
}



1;
