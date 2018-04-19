package SSHTEST;
use strict;
use warnings;
use Exporter;

use File::Temp qw(tempfile);
use PRIVATE;

our @ISA        = qw(Exporter);
our @EXPORT     = qw(ssh_in_test);

my $IOPROXY     = '../ioproxyd';
my $TEMPLATE    = 'ioproxyd.XXXX';

my $out_fh;
my $tmp_outfile;

sub ssh_in_test
{	
	my $cfg_fh;
	my $cfg_file;
	my $ofh;
	my $pid;
	my @args;
	my $ret		 = 1;
	$pid		 = -1;
	my $testfile_len = 1983;

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($out_fh, $tmp_outfile) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);

#	push @args, '-f';
	push @args, $cfg_file;

	print $cfg_fh "{\niotype: SSH; dir: src; host: $HOST; ssh_cmd: tail -n 49 -f $TESTFILE;\n",
	    "(iotype: FILE; path: $tmp_outfile;)\n}";

	close $cfg_fh;
	$pid = fork;
	if ($pid == 0) {
	    close $out_fh;
	    exec($IOPROXY, "-f", @args) || die "exec failed: $!\n";
	    exit(0);
	}

	sleep(3);
	$pid = `/usr/bin/pgrep ioproxyd`;

	if (confirm_io($testfile_len)) {
                print "SSH TEST 1: PASS\n";
        } else {
                $ret = 0;
                printf "SSH TEST 1: FAIL\n";
        }

	sleep 10;

	print "HUP: $pid\n";
        kill 'HUP', $pid;

        sleep(3);

        if (confirm_io($testfile_len * 2)) {
                print "SSH TEST 2: PASS\n";
        } else {
                $ret = 0;
                printf "SSH TEST 2: FAIL\n";
        }

	close $out_fh;
	unlink $out_fh;
	unlink $cfg_fh;

	return $ret;
}

sub confirm_io
{
	my $file_len = shift;

	my @fstats;
	my $len = 0;
	my $rfh;

	open $rfh, '<', $tmp_outfile || die "Can't open $tmp_outfile: $!\n";

	# CONFIRM THE FILE HAS SOME LENGTH
	while ($len < $file_len) {
	    @fstats = stat($out_fh);
	    $len = $fstats[7];
	    print "Sleeping...$len $file_len\n";
	    sleep(1);
	}

	if ($fstats[7] >= $file_len) {
	    print "SSH test\tPASS (Len: $file_len fsz: $fstats[7])\n";
	    return 1;
        } else {
            print "SSH test\tFAIL (Len: $file_len fsz: $fstats[7])\n";
            return 0;
        }
}

1;
