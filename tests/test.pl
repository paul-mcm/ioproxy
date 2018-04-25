#!/usr/bin/perl -w 

use FIFOTEST;
use FILETEST;
use SSHTEST;
use SOCKETTEST;
use USOCKTEST;
use PRIVATE;

$SIG{CHLD} = 'IGNORE';
$SIG{TERM} = \&cleanup;
$SIG{INT} = \&cleanup;
$SIG{QUIT} = \&cleanup;

%TESTS = (
#	'file_test'	=>	\&file_test,
#	'fife_in'	=>	\&fifo_in,
#	'fifo_out'	=>	\&fifo_out,
#	'tls_src_cli'	=>	\&tls_src_cli,
#	'tls_dst_cli'	=>	\&tls_dst_cli,
#	'tls_src_serv'	=>	\&tls_src_serv,
#	'tls_dst_serv'	=>	\&tls_dst_serv,
#	'ssh_in'	=>	\&ssh_in_test,
#	'usock_src_srv'	=>	\&usock_src_serv,
);

#######################################
## TESTS
#######################################

foreach $k (keys %TESTS) {
	if ( &{$TESTS{$k}} ) {
	    print "==TEST PASSED\n";
	} else {
	    print "==TEST FAILED\n";
	}
	print "======================================\n\n";
}

cleanup();

sub cleanup()
{
    $pid = `/usr/bin/pgrep ioproxyd`;
    kill 'TERM', $pid;
    exit(0);
}

