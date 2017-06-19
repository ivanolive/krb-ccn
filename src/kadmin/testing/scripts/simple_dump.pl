#!/usr/bin/perl

#
# $Id$
#

## ovsec_adm_export format
## [0]"policy" [1]name [2]pw_min_life [3]pw_max_life [4]pw_min_length [5]pw_min_classes [6]pw_history_num [7]policy_refcnt
## [0]"princ" [1]name [2]policy [3]aux_attributes [4]old_key_len [5]admin_history_kvno [6..]old_keys
$oaevers = "1.0";

open(SORT, "|sort") || die "Couldn't open pipe to sort for output: $!\n";

open(OAE, "$ENV{'TOP'}/install/admin/ovsec_adm_export|") ||
    die "Couldn't get oae: $!\n";

$header = <OAE>;

die "Not ovsec_adm_export output\n"
    if ($header !~ /^OpenV\*Secure V(\d+\.\d+)/);

$stdinvers = $1;

die "Expected oae version $oaevers, got $stdinvers instead.\n"
    if $stdinvers ne $oaevers;

while(<OAE>) {
    if (/^End of Database/) {
	last;
    } elsif (/^policy/) {
	print SORT;
    } elsif (/^princ/) {
	split(/\t/);

	$_[2] = "\"\"" if !$_[2];

	$_[3] = hex("0x".$_[3]);

	$princ{$_[1]} = sprintf("%s\t0x%04x",@_[2,3]);
    }
}

## kdb_edit ddb format
## [0]strlen(principal) [1]strlen(mod_name) [2]key.length [3]alt_key.length [4]salt_length [5]alt_salt_length [6]principal [7]key.key_type [8]key.contents [9]kvno [10]max_life [11]max_renewable_life [12]mkvno [13]expiration [14]pw_expiration [15]last_pwd_change [16]last_success [17]last_failed [18]fail_auth_count [19]mod_name [20]mod_date [21]attributes [22]salt_type [23]salt [24]alt_key.contents [25]alt_salt [26..33]expansion*8;
$ddbvers = "2.0";

open(DDB, "$ENV{'TOP'}/install/admin/kdb5_edit -r SECURE-TEST.OV.COM -R ddb|") ||
    die "Couldn't get ddb: $!\n";

$header = <DDB>;

die "Not a kdb5_edit ddb\n"
    if ($header !~ /^kdb5_edit load_dump version (\d+\.\d+)/);

$stdinvers = $1;

die "Expected ddb version $ddbvers, got $stdinvers instead.\n"
    if $stdinvers ne $ddbvers;

## [6]principal [9]kvno [19]mod_name [10]max_life [13]expiration [14]pw_expiration [21]attributes // [2]policy [3]aux_attributes

while(<DDB>) {
    split;

    print SORT join("\t","princ",(@_)[6,9,19,10,13,14],
		    sprintf("0x%04x",$_[21]),
		    $princ{$_[6]}),"\n";
}

close(DDB);

for $keytab (@ARGV) {
    open(KLIST, "$ENV{'TOP'}/install/bin/klist -k -t -K FILE:$keytab|") ||
	die "Couldn't list $keytab: $!\n";

    $dummy = <KLIST>;
    $dummy = <KLIST>;
    $dummy = <KLIST>;

    while(<KLIST>) {
	s/^\s+//;
	split;
	printf(SORT "keytab:FILE:%s\t%s-%s\t%s\t%s,%s\n",$keytab,
	       @_[3,0,4,1,2]);
    }
}

close(SORT);
