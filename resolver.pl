#!/usr/bin/perl
#############################################################################################
# DNSMonitor - Resolver.pl
# Copyright (C) 2012, Silas Cutler
#      <Silas.Cutler@BlackListThisDomain.com / scutler@SecureWorks.com>
#
# This program is free software; you can redistribute it and/or modify it under the
#      terms of the GNU General Public License as published by the Free Software
#      Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
#      WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
#      PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
#############################################################################################

use strict;
use warnings;
use DBI;
use Net::DNS;
use Thread::Pool;
use vars qw(%sources);
use Getopt::Long;

my $res = Net::DNS::Resolver->new;
my $threads = 30;
my $running :shared= "true";
my $db_file = "./DNSMon_.db";
my $core_time = time;
my @name_servers = ();

# Signal handlers

$SIG{"INT"}   = sub { quit_handle() };
$SIG{"TERM"}  = sub { quit_handle_now() };
$SIG{"QUIT"}  = sub { quit_handle() };
$SIG{"KILL"}  = sub { quit_handle_now() };


#Input Handling.
my ($debug,$help);
usage() if ( ( 
        ! GetOptions(
                'help|?'          			      =>              \$help,
                'debug|D'          			      =>              \$debug,
                        )
        or defined $help  )  );


#############

sub usage{
        print "DNS Monitor - resolver.pl 1.1 \n - Silas Cutler 2012\n\n";
        print "usage: ./$0
        -debug (-D)		- Debug
			\n";
  exit;
}

if (! -f $db_file) {
        print "+ Database not created.  Please run controller\n";
        usage();
}

my $dbh_main = DBI->connect("dbi:SQLite:dbname=$db_file","", "", {
        PrintError => 0,
        RaiseError => 0,
        AutoCommit => 1 })
        or die "Could not connect to Database!";

my @_threads = ();
my $pool = Thread::Pool->new({
       workers => $threads,
       do => \&resolve_handler,
       autoshutdown => 1,
       });

print "[*] Spinning up...\n";
print "[*] Pulling Domains for Processing up...\n";
##### //main
my %domain_res = ();
pull_domains_for_proc_ttl();

print "[*] Launch!\n";
while ($running eq "true"){
        set_disabled_domains();
		update_dns_servers();
		
        foreach my $_domain (keys %domain_res){
                my $domain_hash = $domain_res{$_domain};
                push(@_threads, $pool->job($_domain , $domain_hash));
        }

        pull_domains_for_proc_ttl();
        print "[*] In Queue..." . keys ( %domain_res ) . "\n" if (defined($debug));
                if (keys ( %domain_res ) == 0){
						print "[S] Sleeping for 20 seconds.  Nothing Waiting\n" if (defined($debug));
                        sleep 20;
                }

        foreach(@_threads){
                my ($finished) = $pool->result_dontwait( $_ );
                if (defined($finished)){
                        #print "Finished - $finished\n";
                        delete $domain_res{$finished};
                }
        }
        if ( ($core_time + 86400) < time ){
                pull_never_seen_domains_for_proc();
                $core_time = time;
        }
}

#######

sub update_dns_servers{
		@name_servers = ();
        my ($dns_server_ip);
        my $request_handle = $dbh_main->prepare('SELECT dns_ip_address from dns_servers where status = "active"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$dns_server_ip );
        while($request_handle->fetch()){
                push(@name_servers, $dns_server_ip);
        }
}
sub pull_domains_for_proc_ttl{

        my @domains_ = ();
        my ($domain_waiting);
        my $request_handle = $dbh_main->prepare("select distinct dns_address from resolved where (((last_seen + ttl) <  " . time . ") and (resolved_ip = 'true' ))");
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain_waiting);
        while($request_handle->fetch()){
                        push(@domains_, $domain_waiting);
        }

		foreach my $dns_related (@domains_){
				my ($domain_id, $domain_ip, $domain_resolved);
				my $request_handle = $dbh_main->prepare("select id, ip_address, resolved_ip from resolved where (dns_address = ? )");
				$request_handle->execute($dns_related);
				$request_handle->bind_columns(undef, \$domain_id, \$domain_ip, \$domain_resolved)
;
				while($request_handle->fetch()){
					$domain_res{$dns_related}{$domain_ip}{"id"} = $domain_id;
					$domain_res{$dns_related}{$domain_ip}{"resolved"} = $domain_resolved;
				}
		}
}

sub pull_never_seen_domains_for_proc{

        my @domains_ = ();
        my ($domain_waiting);
        my $request_handle = $dbh_main->prepare("select distinct dns_address from resolved where first_seen =''");
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain_waiting);
        while($request_handle->fetch()){
                        push(@domains_, $domain_waiting);
        }

		foreach my $dns_related (@domains_){
				my ($domain_id, $domain_ip, $domain_resolved);
				my $request_handle = $dbh_main->prepare("select id, ip_address, resolved_ip from resolved where (dns_address = ? )");
				$request_handle->execute($dns_related);
				$request_handle->bind_columns(undef, \$domain_id, \$domain_ip, \$domain_resolved)
;
				while($request_handle->fetch()){
						$domain_res{$dns_related}{$domain_ip}{"id"} = $domain_id;
						$domain_res{$dns_related}{$domain_ip}{"resolved"} = $domain_resolved;
				}
		}
}
sub set_disabled_domains{
        my @domains_ = ();
        my ($disabled_domain);
        my $request_handle = $dbh_main->prepare("select distinct dns_address from domains where status = 'pending_disable'" );
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$disabled_domain);
        while($request_handle->fetch()){
                print "Domain = $disabled_domain expired\n" if (defined($debug));
				my $request_handle = $dbh_main->prepare("UPDATE domains set status = 'disabled' WHERE ( dns_address =  ?  ) ");
				$request_handle->execute($disabled_domain);
				push(@domains_, $disabled_domain);
        }
                my $request_handle_domains = $dbh_main->prepare("select distinct dns_address from domains where (status = 'active' and expire > 0 and (((expire * 3600 ) + added) > " . time . "))");
        $request_handle_domains->execute();
        $request_handle_domains->bind_columns(undef, \$disabled_domain);
        while($request_handle_domains->fetch()){
                        print "Domain = $disabled_domain expired\n" if (defined($debug));
						my $request_handle = $dbh_main->prepare( "UPDATE domains set status = 'disabled' WHERE ( dns_address =  ?  ) ");
						$request_handle->execute($disabled_domain);
            push(@domains_, $disabled_domain);
        }


        foreach my $dns_related (@domains_){
				my $request_handle = $dbh_main->prepare( "UPDATE resolved set resolved_ip = 'disabled' WHERE ( dns_address =  ?  ) " );
				$request_handle->execute($dns_related);
       }
}

sub resolve_ip{
        my $domain = shift;
		
		if ($#name_servers > -1 ){
			print "Setting Name servers\n";
			$res->nameservers(@name_servers);
		}
		
        my $a_query = $res->search($domain);

        my %resolved = ();
        if ($a_query) {
                foreach my $rr ($a_query->answer) {
                        my $resolved_domain = "";
                        if ($rr->type  eq "CNAME"){
                                $resolved_domain = $rr->cname;
                                next;
                        }
                        elsif ($rr->type  eq "A"){
                                $resolved_domain = $rr->address;
                        }
                        print "$domain -> $resolved_domain\n" if (defined($debug));
                        if ($rr->ttl < 300) {
                                $resolved{$resolved_domain}{"ttl"} = "300";
                        }
                        else{
                                $resolved{$resolved_domain}{"ttl"} = $rr->ttl;
                        }
                        $resolved{$resolved_domain}{"type"} = $rr->type;
                }
        }
        return \%resolved;
}

sub resolve_handler{
        my $dbh_thread = DBI->connect("dbi:SQLite:dbname=$db_file","", "", {
        PrintError => 0,
        RaiseError => 0,
        AutoCommit => 1 })
        or die "Could not connect to Database!";

        my $domain = shift;
        my $domain_hash = shift;
        my $resolved_ref = resolve_ip($domain);

        foreach my $ip_address (keys %{$resolved_ref}) {
                if (! grep {$ip_address eq $_} keys %{$domain_hash}){
		
						my $request_handle = $dbh_thread->prepare( "INSERT INTO resolved VALUES (null, ? , ?, ?, ?, \'" . time . "\', \'" . time . "\', \'true\')" );
						$request_handle->execute($domain,${$resolved_ref}{$ip_address}{"type"},$ip_address,${$resolved_ref}{$ip_address}{"ttl"});
                        print "Added new IP for $domain\n";
                }
                if (grep {$ip_address eq $_} keys %{$domain_hash}){
						my $request_handle = $dbh_thread->prepare( "UPDATE resolved set last_seen = \'" . time . "\', ttl = ?, resolved_ip = 'true' where id = ? ");
						$request_handle->execute(${$resolved_ref}{$ip_address}{"ttl"},${$domain_hash}{$ip_address}{"id"});
                        print "Updated last resolve time for $domain - $ip_address \n" if (defined($debug));
                }

        }
        foreach my $ip_address (keys %{$domain_hash}) {
                if ((! grep {$ip_address eq $_} keys %{$resolved_ref}) && (${$domain_hash}{$ip_address}{"resolved"} eq "true")){
						my $request_handle = $dbh_thread->prepare( "UPDATE resolved set resolved_ip = 'false' where id = ?");
						$request_handle->execute(${$domain_hash}{$ip_address}{"id"});
                        print "Domain $domain did not resolve to $ip_address.\n" if (defined($debug));
                }
        }


        return "$domain";
}

sub quit_handle_now{
        $running = "false";
    print "[*] Shutting down now!...\n";
    print "[*] Killing Threads!...\n";
    $pool->abort;
    exit 0;
}

sub quit_handle{
        $running = "false";
    print "[*] Shutting down!...\n";
        print "[*] Waiting for jobs to finish . . . !...(May take a moment)     \n";
    $pool->shutdown;
    exit 0;
}
