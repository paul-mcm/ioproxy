#!/usr/bin/perl -w 

use FIFOTEST;
use FILETEST;
use SSHTEST;
use SOCKETTEST;

$SIG{CHLD} = 'IGNORE';
$SIG{TERM} = \&cleanup;
$SIG{INT} = \&cleanup;
$SIG{QUIT} = \&cleanup;

%TESTS = (
#	'file_test'	=>	\&file_test,
#	'fife_in'	=>	\&fifo_in,
#	'fifo_out'	=>	\&fifo_out,
#	'tls_cli'	=>	\&tls_cli,
	'tls_serv'	=>	\&tls_cli,
#	'ssh_in'	=>	\&ssh_in,
);

#######################################
## FIFOs
#######################################

foreach $k (keys %TESTS) {
	if ( &{$TESTS{$k}} ) {
	    print "==TEST PASSED\n";
	} else {
	    print "==TEST FAILED\n";
	}
	print "======================================\n\n";
}


cleanup;

sub cleanup()
{
    $pid = `/usr/bin/pgrep ioproxyd`;
    kill 'TERM', $pid;
    exit(0);
}

