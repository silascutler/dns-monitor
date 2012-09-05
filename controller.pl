#!/usr/bin/perl
#############################################################################################
# DNSMonitor - Controller.pl
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
use Getopt::Long;
use Net::DNS;


# ----- ARGUMENTS ----- #
my $db_file = "./DNSMon_.db";

my $dbh = DBI->connect("dbi:SQLite:dbname=$db_file","", "", {
        PrintError => 0,
        RaiseError => 0,
        AutoCommit => 1 })
        or die "Could not connect to Database!";
init();

my $res = Net::DNS::Resolver->new;
my @name_servers = ();

#Input Handling.
my ($add_domain, $rem_domain,$help, $list_domains_active, $list_domains_disabled, $dis_domain, $sear_domain, $sear_ip, $list_ip_changes, $expire_time, $add_dns_server, $rem_dns_server,$list_dns_servers);
usage() if ( ( @ARGV < 1 or
        ! GetOptions(
                'help|?'          			      =>              \$help,
                'add|a=s'          			      =>              \$add_domain,
                'expire|e=s'      			      =>              \$expire_time,
                'remove|r=s'           			  =>              \$rem_domain,
                'list-active|la'      			  =>              \$list_domains_active,
                'list-disabled|ld'    		  	  =>              \$list_domains_disabled,
                'find-dns|fd=s'   	        	  =>              \$sear_domain,
                'find-ip|fi=s'       		   	  =>              \$sear_ip,
                'add-dns-server|adns=s'        	  =>              \$add_dns_server,
                'rem-dns-server|rdns=s'       	  =>              \$rem_dns_server,
				'list-dns-sesrver|ldns'			  =>			  \$list_dns_servers,
                'changes|c'                       =>              \$list_ip_changes
				
                        )
        or defined $help  )  );

if ( defined($expire_time) && $expire_time =~ /\D/ ) {  print " [X] Expire  time must be numerical\n"; exit; }
if ( defined($add_domain))              { add_domain($add_domain);                      }
if ( defined($rem_domain))              { rem_domain($rem_domain);                      }
if ( defined($list_domains_active))     { list_domains_active ();                       }
if ( defined($list_domains_disabled))   { list_domains_disabled ();                     }
if ( defined($sear_domain))             { get_resolved_ips ($sear_domain);              }
if ( defined($sear_ip))                 { get_resolved_domains ($sear_ip);              }
if ( defined($list_ip_changes))         { list_ip_changes ($sear_ip);                   }
if ( defined($add_dns_server))          { add_dns_server ($add_dns_server);              }
if ( defined($rem_dns_server))          { rem_dns_server ($rem_dns_server);              }
if ( defined($list_dns_servers))        { list_dns_server_active ();                   }
#############

sub usage{
        print "DNS Monitor - Controller.pl 1.1 \n - Silas Cutler 2012\n\n";
        print "usage: ./$0
        -add    ( -a )  <domain>   		- Add Domain for monitoring
			-expire ( -e )        	    - Monitor for changes for X hours
        -remove ( -r ) <domain>   		- Delete Domain from monitoring
        -list-active (-la)       	  	- List all Active Domains being monitored
        -list-disabled  (-ld)     		- List all Disabled Domains
        --------------
        -find-dns ( -fd ) <domain>  	- Find IP resolutions of a domain
        -find-ip  ( -fi ) <domain>  	- Find IP resolutions of a domain
        --------------
        -add-dns-server   (-adns  )     - add DNS server
        -rem-dns-server   (-rdns  )     - remove DNS server
        -list-dns-sesrver (-ldns  )     - List all DNS servers
        --------------
        -changes   (-c  )               - List all changes from the past 24 hours
   \n";
  exit;
}

## Initialize.  Ensure that database and tables exists.  If not, Create
sub init{
        $dbh->do('
                CREATE TABLE IF NOT EXISTS domains(
                        id                     INTEGER         PRIMARY KEY     Autoincrement,
                        dns_address             text            UNIQUE  NOT NULL,
                        added                   text                                    NOT NULL,
                                                expire                                  text,
                                                status                                  text
                );)');

        $dbh->do('
                CREATE TABLE IF NOT EXISTS resolved (
                        id                      INTEGER         PRIMARY KEY     Autoincrement,
                        dns_address             text               NOT NULL,
                        type                    text               NOT NULL,
                        ip_address              text               NOT NULL,
                        ttl                     int                        NOT NULL,
                        first_seen              text               NOT NULL,
                        last_seen               text               NOT NULL,
                        resolved_ip                             text            NOT NULL,
                        FOREIGN KEY(dns_address) REFERENCES     domains(dns_address) )
                        ');
		        $dbh->do('
                CREATE TABLE IF NOT EXISTS dns_servers (
                        id                      INTEGER         PRIMARY KEY     Autoincrement,
                        dns_ip_address             text               NOT NULL,
						status 					text			    NOT NULL
						)
                        ');
}

sub add_domain{
        my $domain = shift;
        print "+ Adding Domain $domain\n";
                my $expire = 0;
                if ( defined($expire_time))         { $expire = $expire_time;     }

        if ($domain !~ m/[0-9A-Za-z\-]+\.[0-9A-Za-z\-]{2,}/ ) {
                print "- Bad Domain Name \( $domain \) \n";
                exit;
        }
                my $domain_ref = pull_all_domains();
                if (grep {$domain =~ /^$_$/ } @{$domain_ref}) {
						my $request_handle = $dbh->prepare("UPDATE domains set status = 'active' WHERE ( dns_address =  ?  ) ");
						request_handle->execute($domain);
                                print "Domain existed in Database.  Setting to active\n";
                }
                else{
						my $request_handle = $dbh->prepare("INSERT INTO domains VALUES ( null,  ? ,\'" . time . "\' , ? ,\'active\'  ) " );
						$request_handle->execute($domain, $expire);
						
                }
        resolve_ip($domain);
}

sub rem_domain{
        my $domain = shift;

        my $domain_list_ref = pull_all_domains();
        if (grep {$domain =~ /^$_$/i } @{$domain_list_ref}) {
				my $request_handle = $dbh->prepare("UPDATE domains set status = 'pending_disable' WHERE ( dns_address =  ?  ) " );
				$request_handle->execute($domain);
                print "+ Removed Domain \( $domain \)\n";
        } else {
                print "+ Domain not in database\n";
        }
}

sub pull_all_domains{
        my @domains_ = ();
        my ($domain);
        my $request_handle = $dbh->prepare('SELECT dns_address from domains');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain );
        while($request_handle->fetch()){
                push(@domains_, $domain);
        }
        return \@domains_;
}

sub list_domains_active{
        my ($domain);
        my $count = 0;

        my $request_handle = $dbh->prepare('SELECT dns_address from domains where status = "active"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain );
        while($request_handle->fetch()){
                        if ($domain =~ /\./){
                                $count++;
                print " [*] $domain\n";
            }
        }
        print "\n Total = $count\n";
}

sub list_domains_disabled{
        my ($domain);
                my $count = 0;
        my $request_handle = $dbh->prepare('SELECT dns_address from domains where status != "active"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain );
        while($request_handle->fetch()){
                        if ($domain =~ /\./){
                                $count++;
                print " [*] $domain\n";
            }
        }
        print "\n Total = $count\n";
}

sub resolve_ip{
        my $domain = shift;
		update_dns_servers();
		if ($#name_servers > -1 ){
			print "Setting Name servers\n";
			$res->nameservers(@name_servers);
		}
        my $a_query = $res->search($domain);
        my @resolved = ();
        if ($a_query) {
                foreach my $rr ($a_query->answer) {
                        my $resolved_domain = "";
                        #print $rr->type, "\n";
                        if ($rr->type  eq "CNAME"){
                                #print $rr->cname, "\n";
                                $resolved_domain = $rr->cname;
                                                                next;
                        }
                        elsif ($rr->type  eq "A"){
                                #print $rr->address, "\n";
                                $resolved_domain = $rr->address;
                        }

                        print " [*] $domain, $resolved_domain " .  $rr->type . ", " . $rr->ttl . "\n";
								
						my $request_handle = $dbh->prepare("INSERT INTO resolved VALUES (null, ? , ?, ?, ?, \'" . time . "\', \'" . time . "\', \'true\')");
						$request_handle->execute($domain,$rr->type,$resolved_domain,$rr->ttl);
                        }
        }
		else{
			my $request_handle = $dbh->prepare("INSERT INTO resolved VALUES (null, ? , \'\', \'\', \'\', \'\', \'" . time . "\', \'false\')" );
			$request_handle->execute($domain);
		}
}

sub get_resolved_ips{
        my $req_domain = shift;
                my $count = 0;
        my ($domain);
        my $request_handle = $dbh->prepare('SELECT ip_address from resolved where dns_address = "' . $req_domain . '"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain );
        while($request_handle->fetch()){
                        if ($domain =~ /\./){
                                $count++;
                print " [*] $domain\n";

                        }
        }
                                print "\n Total = $count\n";
}

sub get_resolved_domains{
        my $req_ip = shift;
        my $count = 0;
        my ($ip_addr);
        my $request_handle = $dbh->prepare('SELECT dns_address from resolved where ip_address = "' . $req_ip . '"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$ip_addr );
        while($request_handle->fetch()){
                        if ($ip_addr =~ /\./){
                                $count++;
                print " [*] $ip_addr\n";
                        }
        }
                                print "\n Total = $count\n";
}

sub list_ip_changes{
        my $count = 0;
                my $back_time = time - 86400;
        my ($dns_address, $ip_addr);
        my $request_handle = $dbh->prepare('SELECT distinct dns_address, ip_address from resolved where first_seen > ' . $back_time);
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$dns_address, \$ip_addr );
        while($request_handle->fetch()){
                        if ($ip_addr =~ /\./){
                                $count++;
                print " [*] $dns_address -> $ip_addr\n";
            }
        }
        print "\n Total = $count\n";



}

sub add_dns_server{
        my $dns_server = shift;
        print "+ Adding DNS Server $dns_server\n";

        if ($dns_server !~ m/^[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*$/ ) {
                print "- Bad DNS Server IP \( $dns_server \) \n";
                exit;
        }
        my $domain_ref = pull_all_dns_servers();
		if (grep {$dns_server =~ /^$_$/ } @{$domain_ref}) {
		        my $request_handle = $dbh->prepare("UPDATE dns_servers set status = 'active' WHERE ( dns_ip_address = ?  ) ");
				$request_handle->execute($dns_server);
				print "DNS Server existed in Database.  Setting to active\n";
		}
		else{
		#		$dbh->do( "INSERT INTO dns-servers VALUES ( null,  \'". $dns_server. "\' ,\'active\'  ) " )
		#			or die "X Duplicate DNS Server!";
		        my $request_handle = $dbh->prepare("INSERT INTO dns_servers VALUES ( null, ? ,\'active\'  ) ");
				$request_handle->execute($dns_server);
				print "Added DNS Server - $dns_server\n";		
		}
}

sub rem_dns_server{
        my $dns_server = shift;

        my $domain_list_ref = pull_all_dns_servers();
        if (grep {$dns_server =~ /^$_$/ } @{$domain_list_ref}) {
		        my $request_handle = $dbh->prepare("UPDATE dns_servers set status = 'disable' WHERE ( dns_ip_address =  ?  )  ");
					$request_handle->execute($dns_server);
                print "+ Removed DNS Server \( $dns_server \)\n";
        } else {
                print "+ DNS Server not in database\n";
        }
}

sub pull_all_dns_servers{
        my @domains_ = ();
        my ($domain);
        my $request_handle = $dbh->prepare('SELECT dns_ip_address from dns_servers');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain );
        while($request_handle->fetch()){
                push(@domains_, $domain);
        }
        return \@domains_;
}

sub list_dns_server_active{
        my ($domain);
        my $count = 0;

        my $request_handle = $dbh->prepare('SELECT dns_ip_address from dns_servers where status = "active"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$domain );
        while($request_handle->fetch()){
			if ($domain =~ /\./){
				$count++;
				print " [*] $domain\n";
            }
        }
        print "\n Total = $count\n";
}

sub update_dns_servers{
		@name_servers = ();
        my ($dns_server_ip);
        my $request_handle = $dbh->prepare('SELECT dns_ip_address from dns_servers where status = "active"');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$dns_server_ip );
        while($request_handle->fetch()){
                push(@name_servers, $dns_server_ip);
        }
}

print "\n";
##\\Fin


