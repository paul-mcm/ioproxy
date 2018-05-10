package FIFOTEST;
use strict;
use warnings;
use Exporter;

use File::Temp qw(tempfile);
use POSIX qw(mkfifo);
use IO::Poll qw(POLLRDNORM POLLWRNORM POLLIN POLLHUP);
use Fork;

our @ISA	= qw(Exporter);
our @EXPORT 	= qw(fifo_in fifo_out);

my $INPUT	= "a long string of text that has no meaning\n";
my $IOPROXY	= '../ioproxyd';
my $TEMPLATE	= 'ioproxyd.XXXX';
my $BUFCNT	= 64;

my $fifo;
my $cfg_fh;
my $cfg_file;
my $out_fh;
my $tmp_outfile;
my $in_fh;
my $tmp_infile;
my $ofh;
my $pid;
my $len;
my $i;
my @forkargs;

sub fifo_in
{	
	my @fstats;

	$fifo = '/tmp/TESTFIFO';
	$pid = -1;

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($out_fh, $tmp_outfile) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	mkfifo($fifo, 0700);

	print $cfg_fh "{\niotype: FIFO; dir: src; path: $fifo;\n", 
	"(iotype: FILE; path: $tmp_outfile;)\n}";

	close $cfg_fh;
	close $out_fh;

	push @forkargs, $IOPROXY;
	push @forkargs, "-f";
	push @forkargs, $cfg_file;
	fork_exec(\@forkargs) || die "Error exec'ing ioproxyd";

	sleep(5);

	open $in_fh, ">", $fifo or die "FIFO OPEN FAILED: $!\n"; 
	$ofh = select($in_fh);
	$| = 1;
	select($ofh);

	print "INPUTTING TO $fifo\n";
	for ($i = 0; $i < $BUFCNT; $i++) {
	    print $in_fh "$INPUT" || die "print failed: $!\n";
	}

	close $in_fh;
	
	print "WROTE " . (length($INPUT) * $BUFCNT) . " bytes to FIFO\n";
	$len = 0;
	while ($len < (length($INPUT) * $BUFCNT)) {
	    @fstats = stat($tmp_outfile);
	    $len = $fstats[7];
	    printf("LENGTH IS $len\n");
	    sleep(1);
	}

	unlink($fifo);
	unlink $tmp_outfile;
	unlink $cfg_file;
	$pid = `/usr/bin/pgrep ioproxyd`;
	kill('TERM', $pid);

	if ((length($INPUT) * $BUFCNT) == $fstats[7]) {
	    print "fifo_in_test\tPASS (Input: " . (length($INPUT) * $BUFCNT) . " fsz: $fstats[7])\n";
	    return 1;
	} else {
	    print "fifo_in_test\tFAIL: Input len: " . (length($INPUT) * $BUFCNT) . "fsz: $fstats[7])\n";
	    return 0;
	}
}

sub fifo_out
{	
	my $line;

	$pid = -1;
	$fifo = '/tmp/TESTFIFO';

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($in_fh, $tmp_infile) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	mkfifo($fifo, 0700);

	print $cfg_fh "{\niotype: FILE; dir: src; path: $tmp_infile;\n", 
	"(iotype: FIFO; path: $fifo;)\n}";

	close $cfg_fh;

	push @forkargs, $IOPROXY;
	push @forkargs, "-f";
	push @forkargs, $cfg_file;
	fork_exec(\@forkargs) || die "Error exec'ing ioproxyd";

	sleep(5);
	$ofh = select($in_fh);
	$| = 1;
	select($ofh);

	print $in_fh "$INPUT" || die "print failed: $!\n";

	sleep(2);
	$line = `./fifo_io`;
	$len = length($line);
	
	$pid = `/usr/bin/pgrep ioproxyd`;
	kill 'TERM', $pid;
	unlink $fifo;
	unlink $cfg_file;
	unlink $tmp_infile;

	if (length($INPUT) == length($line)) {
	    print "fifo_out_test\tPASS (Input: " . length($INPUT) . " Read: $len)\n";
	    return 1;
	} else {
	    print "fifo_out_test\tFAIL: Input len: " . length($INPUT) . "Line len: $len\n";
	    return 0;
	}
}

1;
