package FORK;
use strict;
use warnings;
use Exporter;

use File::Temp qw(tempfile);

our @ISA        = qw(Exporter);
our @EXPORT     = qw(fork_exec);

sub fork_exec
{
	my ($args) = @_;
	my $prog = shift @$args;
	my $flag = shift @$args;
 	my $pid; 

	$pid = fork;
	if ($pid == 0) {
	    exec($prog, $flag, @$args) || die "exec failed: $!\n";
	} else {
	    return 1;
	}
}

1;
