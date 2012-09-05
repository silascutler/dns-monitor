#!/usr/bin/perl
#############################################################################################
# UpdateDB - Resolver.pl
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

my $db_file = "./DNSMon_.db";

if ( !-f $db_file ) {
    print "+ Database not created.  Please run controller\n";
    usage();
}

my $dbh_main = DBI->connect(
    "dbi:SQLite:dbname=$db_file",
    "", "",
    {
        PrintError => 0,
        RaiseError => 0,
        AutoCommit => 1
    }
) or die "Could not connect to Database!";

$dbh_main->do("Alter table domains add column status text")
  or die "Failed\n";
$dbh_main->do("Alter table domains add column expire text")
  or die "Failed\n";
$dbh_main->do("update domains set status = 'active' ")
  or die "Failed\n";

