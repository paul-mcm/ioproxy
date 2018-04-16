package SSHTEST;
use strict;
use warnings;
use Exporter;

use File::Temp qw(tempfile);

our @ISA        = qw(Exporter);
our @EXPORT     = qw(ssh_in_test);

my $IOPROXY     = '../ioproxyd';
my $TEMPLATE    = 'ioproxyd.XXXX';

my $cfg_fh;
my $cfg_file;
my $out_fh;
my $tmp_outfile;
my $ofh;
my $pid;
my $i;
my $len;
my @args;
my @fstats;

sub ssh_in_test
{	
	$rhost = shift;

	$pid = -1;
	$len = 0;

	($cfg_fh, $cfg_file) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);
	($out_fh, $tmp_outfile) = tempfile($TEMPLATE, UNLINK => 1, TMPDIR => 1);

	push @args, $cfg_file;

	print $cfg_fh "{\niotype: SSH; dir: src; host: $rhost; ssh_cmd: cat /var/log/messages;\n",
	    "(iotype: FILE; path: $tmp_outfile;)\n}";

	close $cfg_fh;
	$pid = fork;
	if ($pid == 0) {
	    close $out_fh;
	    exec($IOPROXY, "-f", @args) || die "exec failed: $!\n";
	    exit(0);
	}

	sleep(3);

	while ($len < 1978) {
	    @fstats = stat($out_fh);
	    $len = $fstats[7];
	    sleep(1);
	}

	$pid = `/usr/bin/pgrep ioproxyd`;
	kill 'TERM', $pid;
	close $out_fh;
	unlink $out_fh;
	unlink $cfg_fh;

	if ($len == $fstats[7]) {
	    print "file test\tPASS (Len: $len fsz: $fstats[7])\n";
	    return 1;
        } else {
            print "file test\tFAIL (Len: $len fsz: $fstats[7])\n";
            return 0;
        }

}

1;
